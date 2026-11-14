package store

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func user(id, login string) *User {
	return &User{ID: []byte(id), LoginID: []byte(login), Salt: []byte("salt")}
}

func TestBootstrapOnlyOnce(t *testing.T) {
	s := open(t)
	u := user("u1", "l1")
	if err := s.CreateUser(u, Registration{Bootstrap: true}, []byte("idx")); err != nil {
		t.Fatal(err)
	}
	if !u.Admin {
		t.Fatal("bootstrap user is not admin")
	}
	err := s.CreateUser(user("u2", "l2"), Registration{Bootstrap: true}, nil)
	if !errors.Is(err, ErrInvite) {
		t.Fatalf("second bootstrap: %v", err)
	}
}

func TestInviteSingleUseAndKeptOnLoginConflict(t *testing.T) {
	s := open(t)
	if err := s.CreateUser(user("u1", "taken"), Registration{Bootstrap: true}, nil); err != nil {
		t.Fatal(err)
	}
	inv := []byte("invite")
	if err := s.PutInvite(inv, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	err := s.CreateUser(user("u2", "taken"), Registration{InviteID: inv}, nil)
	if !errors.Is(err, ErrLoginTaken) {
		t.Fatalf("got %v", err)
	}
	if err := s.CreateUser(user("u3", "free"), Registration{InviteID: inv}, nil); err != nil {
		t.Fatalf("invite was burned by a failed attempt: %v", err)
	}
	u := user("u4", "free2")
	if err := s.CreateUser(u, Registration{InviteID: inv}, nil); !errors.Is(err, ErrInvite) {
		t.Fatalf("invite reused: %v", err)
	}
	if u.Admin {
		t.Fatal("invited user became admin")
	}
}

func TestInviteRace(t *testing.T) {
	s := open(t)
	inv := []byte("invite")
	_ = s.PutInvite(inv, time.Now().Add(time.Hour))
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := string(rune('a' + i))
			if s.CreateUser(user(id, id), Registration{InviteID: inv}, nil) == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("invite used %d times", ok)
	}
}

func TestExpiredInvite(t *testing.T) {
	s := open(t)
	inv := []byte("invite")
	_ = s.PutInvite(inv, time.Now().Add(-time.Second))
	if err := s.CreateUser(user("u", "l"), Registration{InviteID: inv}, nil); !errors.Is(err, ErrInvite) {
		t.Fatal(err)
	}
	if err := s.CreateUser(user("u", "l"), Registration{}, nil); !errors.Is(err, ErrInvite) {
		t.Fatal("registered without invite")
	}
}

func TestSessionsExpireAndSweep(t *testing.T) {
	s := open(t)
	now := time.Unix(1_000_000, 0)
	s.now = func() time.Time { return now }
	_ = s.PutSession([]byte("a"), now.Add(time.Minute), []byte("sealed"))
	_ = s.PutSession([]byte("b"), now.Add(-time.Minute), []byte("sealed"))
	_ = s.PutSession([]byte("c"), now.Add(-time.Minute), []byte("sealed"))
	if v, err := s.Session([]byte("a")); err != nil || string(v) != "sealed" {
		t.Fatalf("live session: %v", err)
	}
	if _, err := s.Session([]byte("b")); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired session returned")
	}
	n, err := s.Sweep()
	if err != nil || n != 2 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	if _, err := s.Session([]byte("a")); err != nil {
		t.Fatal("sweep removed a live session")
	}
}

func TestUpdateAndDeleteUser(t *testing.T) {
	s := open(t)
	_ = s.CreateUser(user("u1", "l1"), Registration{Bootstrap: true}, []byte("idx"))
	err := s.UpdateUser([]byte("u1"), func(u *User) error { u.Epoch++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	u, _ := s.UserByLogin([]byte("l1"))
	if u.Epoch != 1 {
		t.Fatal("update lost")
	}
	if err := s.UpdateUser([]byte("u1"), func(u *User) error { u.ID = []byte("x"); return nil }); err == nil {
		t.Fatal("id change accepted")
	}
	if err := s.DeleteUser([]byte("u1")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UserByLogin([]byte("l1")); !errors.Is(err, ErrNotFound) {
		t.Fatal("login survived deletion")
	}
	if _, err := s.Index([]byte("u1")); !errors.Is(err, ErrNotFound) {
		t.Fatal("index survived deletion")
	}
}

func TestRefusesNewerSchema(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vault.db")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.db.Update(func(tx *bboltTx) error { return tx.Bucket(bMeta).Put(kSchema, u64(schemaVersion+1)) })
	_ = s.Close()
	if _, err := Open(p); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("opened newer schema: %v", err)
	}
}

func TestSnapshot(t *testing.T) {
	s := open(t)
	_ = s.CreateUser(user("u1", "l1"), Registration{Bootstrap: true}, nil)
	dir := t.TempDir()
	if err := s.Snapshot(dir); err != nil {
		t.Fatal(err)
	}
	snap, err := Open(filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Close()
	if _, err := snap.UserByLogin([]byte("l1")); err != nil {
		t.Fatal("snapshot is missing data")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temp files left: %d", len(entries))
	}
}
