package account

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"rima.su/vault/internal/access"
	"rima.su/vault/internal/keys"
	"rima.su/vault/internal/store"
)

var bootstrapCode = bytes.Repeat([]byte{7}, KeySize)

func newService(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(st, keys.ForTest(), BootstrapHash(bootstrapCode)), st
}

func rnd(n int) []byte { return randBytes(n) }

func creds() Credentials {
	return Credentials{Salt: rnd(SaltSize), Iterations: DefaultIterations,
		AuthKey: rnd(KeySize), MetaKey: rnd(KeySize), Keyset: rnd(200)}
}

func recovery() Recovery {
	return Recovery{AuthKey: rnd(KeySize), MetaKey: rnd(KeySize), Keyset: rnd(200)}
}

// FakeRegister builds a valid registration as a browser would.
func FakeRegister(login string, invite []byte) RegisterInput {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	x, _ := ecdh.X25519().GenerateKey(rand.Reader)
	xp := x.PublicKey().Bytes()
	return RegisterInput{Login: login, Invite: invite, Creds: creds(), Recovery: recovery(),
		IdentityPub: pub, ExchangePub: xp, IdentitySig: ed25519.Sign(priv, RegisterMessage(pub, xp))}
}

func TestRegisterLoginLogout(t *testing.T) {
	s, _ := newService(t)
	in := FakeRegister("alice", bootstrapCode)
	sess, _, err := s.Register(in)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Authenticate(sess.Token)
	if err != nil || !p.Admin {
		t.Fatalf("auth after register: %v admin=%v", err, p != nil && p.Admin)
	}
	info, err := s.Info(p)
	if err != nil || info.Login != "alice" || !bytes.Equal(info.Keyset, in.Creds.Keyset) {
		t.Fatalf("info: %v %+v", err, info)
	}

	salt, iter, err := s.Prelogin("alice")
	if err != nil || !bytes.Equal(salt, in.Creds.Salt) || iter != DefaultIterations {
		t.Fatal("prelogin returned wrong params")
	}
	sess2, info2, err := s.Login("alice", in.Creds.AuthKey, in.Creds.MetaKey)
	if err != nil || !bytes.Equal(info2.Keyset, in.Creds.Keyset) {
		t.Fatalf("login: %v", err)
	}
	if err := s.Logout(sess2.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(sess2.Token); !errors.Is(err, ErrNoSession) {
		t.Fatal("session survived logout")
	}
	if _, err := s.Authenticate(sess.Token); err != nil {
		t.Fatal("logout killed another session")
	}
}

func TestLoginFailures(t *testing.T) {
	s, _ := newService(t)
	in := FakeRegister("alice", bootstrapCode)
	if _, _, err := s.Register(in); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Login("alice", rnd(KeySize), in.Creds.MetaKey); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong authKey: %v", err)
	}
	if _, _, err := s.Login("alice", in.Creds.AuthKey, rnd(KeySize)); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong metaKey: %v", err)
	}
	if _, _, err := s.Login("nobody", rnd(KeySize), rnd(KeySize)); !errors.Is(err, ErrAuth) {
		t.Fatalf("unknown login: %v", err)
	}
	if _, _, err := s.Login("Alice", in.Creds.AuthKey, in.Creds.MetaKey); !errors.Is(err, ErrBadInput) {
		t.Fatalf("uppercase login: %v", err)
	}
}

func TestPreloginDoesNotRevealAccounts(t *testing.T) {
	s, _ := newService(t)
	a1, i1, _ := s.Prelogin("ghost")
	a2, i2, _ := s.Prelogin("ghost")
	b, _, _ := s.Prelogin("ghost2")
	if !bytes.Equal(a1, a2) || i1 != i2 || len(a1) != SaltSize {
		t.Fatal("fake salt is not stable")
	}
	if bytes.Equal(a1, b) {
		t.Fatal("fake salt is the same for different logins")
	}
}

func TestLoginThrottledPerAccount(t *testing.T) {
	s, _ := newService(t)
	_, _, _ = s.Register(FakeRegister("alice", bootstrapCode))
	var err error
	for i := 0; i < 20; i++ {
		_, _, err = s.Login("alice", rnd(KeySize), rnd(KeySize))
	}
	if !errors.Is(err, ErrThrottled) {
		t.Fatalf("no throttling after 20 failures: %v", err)
	}
}

func TestRegisterValidation(t *testing.T) {
	s, _ := newService(t)
	mut := []func(*RegisterInput){
		func(in *RegisterInput) { in.Login = "ab" },
		func(in *RegisterInput) { in.Login = "-alice" },
		func(in *RegisterInput) { in.Login = "алиса" },
		func(in *RegisterInput) { in.Creds.Iterations = 1000 },
		func(in *RegisterInput) { in.Creds.Salt = rnd(8) },
		func(in *RegisterInput) { in.Creds.MetaKey = in.Creds.AuthKey },
		func(in *RegisterInput) { in.Creds.Keyset = rnd(MaxKeysetSize + 1) },
		func(in *RegisterInput) { in.Recovery.AuthKey = nil },
		func(in *RegisterInput) { in.IdentitySig = rnd(ed25519.SignatureSize) },
		func(in *RegisterInput) { in.ExchangePub = rnd(KeySize + 1) },
	}
	for i, m := range mut {
		in := FakeRegister("alice", bootstrapCode)
		m(&in)
		if _, _, err := s.Register(in); !errors.Is(err, ErrBadInput) {
			t.Errorf("case %d: %v", i, err)
		}
	}
	if _, _, err := s.Register(FakeRegister("alice", rnd(KeySize))); !errors.Is(err, ErrInvite) {
		t.Fatalf("random invite: %v", err)
	}
}

func TestInvites(t *testing.T) {
	s, _ := newService(t)
	admin, _, _ := s.Register(FakeRegister("admin", bootstrapCode))
	ap, _ := s.Authenticate(admin.Token)
	code, _, err := s.CreateInvite(ap)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Register(FakeRegister("admin", code)); !errors.Is(err, ErrLoginTaken) {
		t.Fatalf("duplicate login: %v", err)
	}
	bob, _, err := s.Register(FakeRegister("bob", code))
	if err != nil {
		t.Fatal(err)
	}
	bp, _ := s.Authenticate(bob.Token)
	if bp.Admin {
		t.Fatal("invited user is admin")
	}
	if _, _, err := s.CreateInvite(bp); !errors.Is(err, ErrForbidden) {
		t.Fatal("non-admin created an invite")
	}
	if _, _, err := s.Register(FakeRegister("carol", code)); !errors.Is(err, ErrInvite) {
		t.Fatal("invite reused")
	}
	if _, _, err := s.Register(FakeRegister("carol", bootstrapCode)); !errors.Is(err, ErrInvite) {
		t.Fatal("bootstrap code reused")
	}
}

func TestChangePasswordRevokesSessions(t *testing.T) {
	s, _ := newService(t)
	in := FakeRegister("alice", bootstrapCode)
	s1, _, _ := s.Register(in)
	s2, _, _ := s.Login("alice", in.Creds.AuthKey, in.Creds.MetaKey)
	p, _ := s.Authenticate(s1.Token)

	nc := creds()
	if _, err := s.ChangePassword(p, rnd(KeySize), nc); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong current password: %v", err)
	}
	s3, err := s.ChangePassword(p, in.Creds.AuthKey, nc)
	if err != nil {
		t.Fatal(err)
	}
	for _, old := range []*Session{s1, s2} {
		if _, err := s.Authenticate(old.Token); !errors.Is(err, ErrNoSession) {
			t.Fatal("old session survived password change")
		}
	}
	p3, err := s.Authenticate(s3.Token)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := s.Info(p3); err != nil || info.Login != "alice" {
		t.Fatalf("index unreadable after change: %v", err)
	}
	if _, _, err := s.Login("alice", in.Creds.AuthKey, in.Creds.MetaKey); !errors.Is(err, ErrAuth) {
		t.Fatal("old password still works")
	}
	if _, _, err := s.Login("alice", nc.AuthKey, nc.MetaKey); err != nil {
		t.Fatal("new password does not work")
	}
}

func TestRecovery(t *testing.T) {
	s, _ := newService(t)
	in := FakeRegister("alice", bootstrapCode)
	old, _, _ := s.Register(in)

	if _, err := s.RecoveryKeyset("alice", rnd(KeySize)); !errors.Is(err, ErrAuth) {
		t.Fatal("recovery keyset without the code")
	}
	ks, err := s.RecoveryKeyset("alice", in.Recovery.AuthKey)
	if err != nil || !bytes.Equal(ks, in.Recovery.Keyset) {
		t.Fatalf("recovery keyset: %v", err)
	}
	bad := in.Recovery
	bad.MetaKey = rnd(KeySize)
	if _, err := s.Recover("alice", bad, creds(), recovery()); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong recovery metaKey: %v", err)
	}

	nc, nr := creds(), recovery()
	sess, err := s.Recover("alice", in.Recovery, nc, nr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(old.Token); !errors.Is(err, ErrNoSession) {
		t.Fatal("old session survived recovery")
	}
	p, _ := s.Authenticate(sess.Token)
	if info, err := s.Info(p); err != nil || info.Login != "alice" {
		t.Fatalf("index after recovery: %v", err)
	}
	if _, err := s.Recover("alice", in.Recovery, creds(), recovery()); !errors.Is(err, ErrAuth) {
		t.Fatal("recovery code reused")
	}
	if _, err := s.RecoveryKeyset("alice", nr.AuthKey); err != nil {
		t.Fatal("new recovery code does not work")
	}
}

func TestSessionExpiry(t *testing.T) {
	s, _ := newService(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	sess, _, _ := s.Register(FakeRegister("alice", bootstrapCode))

	now = now.Add(SessionIdle - time.Minute)
	if _, err := s.Authenticate(sess.Token); err != nil {
		t.Fatal("session expired early")
	}
	now = now.Add(SessionIdle - time.Minute) // still alive: the previous call touched it
	if _, err := s.Authenticate(sess.Token); err != nil {
		t.Fatal("idle timeout was not extended")
	}
	now = now.Add(SessionIdle + time.Second)
	if _, err := s.Authenticate(sess.Token); !errors.Is(err, ErrNoSession) {
		t.Fatal("idle session accepted")
	}
}

func TestSessionAbsoluteLifetime(t *testing.T) {
	s, _ := newService(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	sess, _, _ := s.Register(FakeRegister("alice", bootstrapCode))
	for i := 1; i < int(SessionLifetime/time.Hour); i++ {
		now = now.Add(time.Hour)
		if _, err := s.Authenticate(sess.Token); err != nil {
			t.Fatal("active session died early")
		}
	}
	now = now.Add(2 * time.Hour)
	if _, err := s.Authenticate(sess.Token); !errors.Is(err, ErrNoSession) {
		t.Fatal("session outlived its absolute lifetime")
	}
}

func TestBadTokens(t *testing.T) {
	s, _ := newService(t)
	for _, tok := range [][]byte{nil, rnd(5), rnd(TokenSize)} {
		if _, err := s.Authenticate(tok); !errors.Is(err, ErrNoSession) {
			t.Fatalf("token %x accepted", tok)
		}
	}
}

func TestDeleteAccount(t *testing.T) {
	s, _ := newService(t)
	in := FakeRegister("alice", bootstrapCode)
	sess, _, _ := s.Register(in)
	p, _ := s.Authenticate(sess.Token)
	if err := s.DeleteAccount(p, rnd(KeySize)); !errors.Is(err, ErrAuth) {
		t.Fatal("deleted with wrong password")
	}
	if err := s.DeleteAccount(p, in.Creds.AuthKey); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(sess.Token); !errors.Is(err, ErrNoSession) {
		t.Fatal("session survived account deletion")
	}
	if _, _, err := s.Login("alice", in.Creds.AuthKey, in.Creds.MetaKey); !errors.Is(err, ErrAuth) {
		t.Fatal("deleted account can log in")
	}
}

func TestAuthorizeUnknownObject(t *testing.T) {
	s, _ := newService(t)
	sess, _, _ := s.Register(FakeRegister("alice", bootstrapCode))
	p, _ := s.Authenticate(sess.Token)
	for _, act := range []access.Action{access.Read, access.Write, access.Share, access.Delete} {
		if err := s.Authorize(p, rnd(16), act); !errors.Is(err, ErrNotFound) {
			t.Fatalf("action %d on unknown object: %v", act, err)
		}
	}
	objs, err := s.Objects(p)
	if err != nil || len(objs) != 0 {
		t.Fatalf("objects: %v %d", err, len(objs))
	}
}

func FuzzValidLogin(f *testing.F) {
	for _, s := range []string{"alice", "a.b-c_d", "..", "a", "ALICE", "al\x00ce"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !ValidLogin(s) {
			return
		}
		if len(s) < MinLoginLen || len(s) > MaxLoginLen {
			t.Fatalf("bad length accepted: %q", s)
		}
		for _, c := range []byte(s) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
				t.Fatalf("bad char accepted: %q", s)
			}
		}
	})
}
