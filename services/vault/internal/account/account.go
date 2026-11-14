// Package account implements registration, login, sessions and recovery.
//
// The password never reaches the server. The browser derives from it:
//
//	authKey  proves the password (server keeps only HMAC(pepper, authKey))
//	metaKey  unseals the user's metadata key; held by the server only inside
//	         sessions, which are themselves sealed by the session token
//	wrapKey  wraps the user's private keys; never leaves the browser
package account

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"rima.su/vault/internal/access"
	"rima.su/vault/internal/keys"
	"rima.su/vault/internal/ratelimit"
	"rima.su/vault/internal/seal"
	"rima.su/vault/internal/store"
)

const (
	KeySize           = 32
	SaltSize          = 32
	TokenSize         = 32
	UserIDSize        = 16
	MinIterations     = 600_000
	MaxIterations     = 10_000_000
	DefaultIterations = 600_000
	MinKeysetSize     = seal.Overhead + 16
	MaxKeysetSize     = 4096
	MinLoginLen       = 3
	MaxLoginLen       = 32

	SessionLifetime = 12 * time.Hour
	SessionIdle     = 2 * time.Hour
	sessionTouch    = 5 * time.Minute
	InviteLifetime  = 7 * 24 * time.Hour
)

var (
	ErrBadInput   = errors.New("bad input")
	ErrAuth       = errors.New("invalid credentials")
	ErrInvite     = store.ErrInvite
	ErrLoginTaken = store.ErrLoginTaken
	ErrNoSession  = errors.New("no session")
	ErrForbidden  = errors.New("forbidden")
	ErrThrottled  = errors.New("too many attempts")
	ErrNotFound   = errors.New("not found")
)

// RegisterMessage is what the browser signs with its new identity key; the
// signature proves possession and binds the exchange key to the identity.
func RegisterMessage(identityPub, exchangePub []byte) []byte {
	return seal.AAD("trebuchet register v1", identityPub, exchangePub)
}

// Credentials are the password-derived values sent by the browser.
type Credentials struct {
	Salt       []byte
	Iterations int
	AuthKey    []byte
	MetaKey    []byte
	Keyset     []byte // private keys wrapped by wrapKey (opaque here)
}

// Recovery holds the values derived from the recovery code.
type Recovery struct {
	AuthKey []byte
	MetaKey []byte
	Keyset  []byte // private keys wrapped by the recovery wrap key
}

type RegisterInput struct {
	Login       string
	Invite      []byte
	Creds       Credentials
	Recovery    Recovery
	IdentityPub []byte
	ExchangePub []byte
	IdentitySig []byte
}

type Session struct {
	Token   []byte
	Expires time.Time
}

// Principal is an authenticated caller. metaKey stays inside this package.
type Principal struct {
	UserID    []byte
	Admin     bool
	sessionID []byte
	metaKey   []byte
}

type Info struct {
	Login       string
	UserID      []byte
	IdentityPub []byte
	ExchangePub []byte
	Keyset      []byte
	Admin       bool
	CreatedAt   time.Time
}

type Service struct {
	st            *store.Store
	k             *keys.Keys
	bootstrapHash []byte
	attempts      *ratelimit.Limiter
	now           func() time.Time
	dummyHash     []byte
}

// New creates the service. bootstrapHash is SHA-256 of the one-time code that
// registers the first admin (nil disables bootstrap).
func New(st *store.Store, k *keys.Keys, bootstrapHash []byte) *Service {
	dummy := make([]byte, KeySize)
	_, _ = rand.Read(dummy)
	return &Service{
		st:            st,
		k:             k,
		bootstrapHash: bootstrapHash,
		// Per account, independent of IP: 10 failures, then one per 3 minutes.
		attempts:  ratelimit.New(20, time.Hour, 10, 100_000),
		now:       time.Now,
		dummyHash: k.AuthHash(dummy),
	}
}

// BootstrapHash is the value to configure for a bootstrap code.
func BootstrapHash(code []byte) []byte {
	h := sha256.Sum256(code)
	return h[:]
}

// ValidLogin accepts 3-32 of [a-z0-9._-], starting and ending with [a-z0-9].
func ValidLogin(s string) bool {
	if len(s) < MinLoginLen || len(s) > MaxLoginLen {
		return false
	}
	alnum := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !alnum(c) && !(c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return alnum(s[0]) && alnum(s[len(s)-1])
}

func validCreds(c Credentials) bool {
	return len(c.Salt) == SaltSize &&
		c.Iterations >= MinIterations && c.Iterations <= MaxIterations &&
		len(c.AuthKey) == KeySize && len(c.MetaKey) == KeySize &&
		len(c.Keyset) >= MinKeysetSize && len(c.Keyset) <= MaxKeysetSize &&
		!bytes.Equal(c.AuthKey, c.MetaKey)
}

func validRecovery(r Recovery) bool {
	return len(r.AuthKey) == KeySize && len(r.MetaKey) == KeySize &&
		len(r.Keyset) >= MinKeysetSize && len(r.Keyset) <= MaxKeysetSize &&
		!bytes.Equal(r.AuthKey, r.MetaKey)
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// --- sealed values ---

type index struct {
	V       int      `json:"v"`
	Login   string   `json:"login"`
	Objects [][]byte `json:"objects"`
}

func metaAAD(userID []byte) []byte     { return seal.AAD("trebuchet meta-priv v1", userID) }
func recoveryAAD(userID []byte) []byte { return seal.AAD("trebuchet meta-priv recovery v1", userID) }
func indexAAD(userID []byte) []byte    { return seal.AAD("trebuchet index v1", userID) }

func indexKey(metaPriv []byte) []byte { return seal.Derive(metaPriv, "trebuchet index v1") }

func sealIndex(userID, metaPriv []byte, idx *index) ([]byte, error) {
	data, err := json.Marshal(idx)
	if err != nil {
		return nil, err
	}
	return seal.Seal(indexKey(metaPriv), data, indexAAD(userID))
}

// --- registration ---

func (s *Service) registration(invite []byte) (store.Registration, bool) {
	if len(invite) != KeySize {
		return store.Registration{}, false
	}
	if len(s.bootstrapHash) == sha256.Size &&
		subtle.ConstantTimeCompare(BootstrapHash(invite), s.bootstrapHash) == 1 {
		return store.Registration{Bootstrap: true}, true
	}
	return store.Registration{InviteID: s.k.InviteID(invite)}, true
}

func (s *Service) Register(in RegisterInput) (*Session, *Info, error) {
	if !ValidLogin(in.Login) || !validCreds(in.Creds) || !validRecovery(in.Recovery) ||
		len(in.IdentityPub) != ed25519.PublicKeySize || len(in.ExchangePub) != KeySize ||
		len(in.IdentitySig) != ed25519.SignatureSize {
		return nil, nil, ErrBadInput
	}
	if !ed25519.Verify(in.IdentityPub, RegisterMessage(in.IdentityPub, in.ExchangePub), in.IdentitySig) {
		return nil, nil, ErrBadInput
	}
	if _, err := ecdh.X25519().NewPublicKey(in.ExchangePub); err != nil {
		return nil, nil, ErrBadInput
	}
	reg, ok := s.registration(in.Invite)
	if !ok {
		return nil, nil, ErrInvite
	}

	metaPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	priv := metaPriv.Bytes()
	defer clear(priv)

	id := randBytes(UserIDSize)
	sealedPriv, err := seal.Seal(in.Creds.MetaKey, priv, metaAAD(id))
	if err != nil {
		return nil, nil, err
	}
	sealedRec, err := seal.Seal(in.Recovery.MetaKey, priv, recoveryAAD(id))
	if err != nil {
		return nil, nil, err
	}
	sealedIdx, err := sealIndex(id, priv, &index{V: 1, Login: in.Login, Objects: [][]byte{}})
	if err != nil {
		return nil, nil, err
	}

	u := &store.User{
		ID:                 id,
		LoginID:            s.k.LoginID(in.Login),
		Salt:               in.Creds.Salt,
		Iterations:         in.Creds.Iterations,
		AuthHash:           s.k.AuthHash(in.Creds.AuthKey),
		MetaPub:            metaPriv.PublicKey().Bytes(),
		MetaPrivSealed:     sealedPriv,
		RecoveryHash:       s.k.RecoveryHash(in.Recovery.AuthKey),
		RecoveryPrivSealed: sealedRec,
		IdentityPub:        in.IdentityPub,
		ExchangePub:        in.ExchangePub,
		Keyset:             in.Creds.Keyset,
		RecoveryKeyset:     in.Recovery.Keyset,
	}
	if err := s.st.CreateUser(u, reg, sealedIdx); err != nil {
		return nil, nil, err
	}
	sess, err := s.newSession(u.ID, u.Epoch, in.Creds.MetaKey)
	if err != nil {
		return nil, nil, err
	}
	return sess, &Info{Login: in.Login, UserID: u.ID, IdentityPub: u.IdentityPub,
		ExchangePub: u.ExchangePub, Keyset: u.Keyset, Admin: u.Admin,
		CreatedAt: time.Unix(u.CreatedAt, 0)}, nil
}

// --- login ---

// Prelogin returns the KDF parameters for a login. Unknown logins get a
// stable fake salt, so the answer does not reveal whether an account exists.
func (s *Service) Prelogin(login string) (salt []byte, iterations int, err error) {
	if !ValidLogin(login) {
		return nil, 0, ErrBadInput
	}
	lid := s.k.LoginID(login)
	u, err := s.st.UserByLogin(lid)
	if errors.Is(err, store.ErrNotFound) {
		return s.k.FakeSalt(lid), DefaultIterations, nil
	}
	if err != nil {
		return nil, 0, err
	}
	return u.Salt, u.Iterations, nil
}

// checkUser finds the user and verifies a secret in near-constant time,
// whether or not the login exists.
func (s *Service) checkUser(login string, hash func(*store.User) []byte, got []byte) (*store.User, error) {
	lid := s.k.LoginID(login)
	if !s.attempts.Allow(string(lid)) {
		return nil, ErrThrottled
	}
	u, err := s.st.UserByLogin(lid)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	want := s.dummyHash
	if u != nil {
		want = hash(u)
	}
	if !hmac.Equal(got, want) || u == nil {
		return nil, ErrAuth
	}
	return u, nil
}

// Login verifies authKey and metaKey and opens a session. It returns the
// user's wrapped keyset, which is never handed out before login: otherwise
// anyone could download it and guess the password offline.
func (s *Service) Login(login string, authKey, metaKey []byte) (*Session, *Info, error) {
	if !ValidLogin(login) || len(authKey) != KeySize || len(metaKey) != KeySize {
		return nil, nil, ErrBadInput
	}
	u, err := s.checkUser(login, func(u *store.User) []byte { return u.AuthHash }, s.k.AuthHash(authKey))
	if err != nil {
		return nil, nil, err
	}
	priv, err := seal.Open(metaKey, u.MetaPrivSealed, metaAAD(u.ID))
	if err != nil {
		return nil, nil, ErrAuth
	}
	clear(priv)
	sess, err := s.newSession(u.ID, u.Epoch, metaKey)
	if err != nil {
		return nil, nil, err
	}
	return sess, &Info{Login: login, UserID: u.ID, IdentityPub: u.IdentityPub,
		ExchangePub: u.ExchangePub, Keyset: u.Keyset, Admin: u.Admin,
		CreatedAt: time.Unix(u.CreatedAt, 0)}, nil
}

// --- sessions ---

type sessionRecord struct {
	V        int    `json:"v"`
	UserID   []byte `json:"uid"`
	Epoch    uint64 `json:"epoch"`
	MetaKey  []byte `json:"meta_key"`
	Created  int64  `json:"created"`
	LastSeen int64  `json:"last_seen"`
}

func (r *sessionRecord) expires() time.Time {
	abs := time.Unix(r.Created, 0).Add(SessionLifetime)
	idle := time.Unix(r.LastSeen, 0).Add(SessionIdle)
	if idle.Before(abs) {
		return idle
	}
	return abs
}

// sessionKeys derives the database key and the sealing key from the token.
// Only the browser has the token, so a stolen disk does not open sessions.
func sessionKeys(token []byte) (id, key []byte) {
	return seal.Derive(token, "trebuchet session id v1"), seal.Derive(token, "trebuchet session seal v1")
}

func (s *Service) putSession(id, key []byte, rec *sessionRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	sealed, err := seal.Seal(key, data, seal.AAD("trebuchet session v1", id))
	clear(data)
	if err != nil {
		return err
	}
	return s.st.PutSession(id, rec.expires(), sealed)
}

func (s *Service) newSession(userID []byte, epoch uint64, metaKey []byte) (*Session, error) {
	token := randBytes(TokenSize)
	id, key := sessionKeys(token)
	now := s.now().Unix()
	rec := &sessionRecord{V: 1, UserID: userID, Epoch: epoch, MetaKey: metaKey, Created: now, LastSeen: now}
	if err := s.putSession(id, key, rec); err != nil {
		return nil, err
	}
	return &Session{Token: token, Expires: rec.expires()}, nil
}

// Authenticate resolves a session token. Sessions die on expiry, on logout,
// and all at once when the account's epoch changes (password change, recovery).
func (s *Service) Authenticate(token []byte) (*Principal, error) {
	if len(token) != TokenSize {
		return nil, ErrNoSession
	}
	id, key := sessionKeys(token)
	sealed, err := s.st.Session(id)
	if err != nil {
		return nil, ErrNoSession
	}
	data, err := seal.Open(key, sealed, seal.AAD("trebuchet session v1", id))
	if err != nil {
		return nil, ErrNoSession
	}
	var rec sessionRecord
	err = json.Unmarshal(data, &rec)
	clear(data)
	if err != nil || rec.V != 1 || len(rec.MetaKey) != KeySize {
		return nil, ErrNoSession
	}
	now := s.now()
	if !now.Before(rec.expires()) {
		_ = s.st.DeleteSession(id)
		return nil, ErrNoSession
	}
	u, err := s.st.UserByID(rec.UserID)
	if err != nil || u.Epoch != rec.Epoch {
		_ = s.st.DeleteSession(id)
		return nil, ErrNoSession
	}
	if now.Sub(time.Unix(rec.LastSeen, 0)) >= sessionTouch {
		rec.LastSeen = now.Unix()
		if err := s.putSession(id, key, &rec); err != nil {
			return nil, err
		}
	}
	return &Principal{UserID: u.ID, Admin: u.Admin, sessionID: id, metaKey: rec.MetaKey}, nil
}

// Logout deletes the session behind token. Unknown tokens are ignored.
func (s *Service) Logout(token []byte) error {
	if len(token) != TokenSize {
		return nil
	}
	id, _ := sessionKeys(token)
	return s.st.DeleteSession(id)
}

// --- authenticated operations ---

func (s *Service) open(p *Principal) (*store.User, []byte, *index, error) {
	u, err := s.st.UserByID(p.UserID)
	if err != nil {
		return nil, nil, nil, ErrNoSession
	}
	priv, err := seal.Open(p.metaKey, u.MetaPrivSealed, metaAAD(u.ID))
	if err != nil {
		return nil, nil, nil, ErrNoSession
	}
	sealedIdx, err := s.st.Index(u.ID)
	if err != nil {
		clear(priv)
		return nil, nil, nil, err
	}
	data, err := seal.Open(indexKey(priv), sealedIdx, indexAAD(u.ID))
	if err != nil {
		clear(priv)
		return nil, nil, nil, err
	}
	var idx index
	if err := json.Unmarshal(data, &idx); err != nil || idx.V != 1 {
		clear(priv)
		return nil, nil, nil, errors.New("corrupt index")
	}
	return u, priv, &idx, nil
}

func (s *Service) Info(p *Principal) (*Info, error) {
	u, priv, idx, err := s.open(p)
	if err != nil {
		return nil, err
	}
	clear(priv)
	return &Info{Login: idx.Login, UserID: u.ID, IdentityPub: u.IdentityPub,
		ExchangePub: u.ExchangePub, Keyset: u.Keyset, Admin: u.Admin,
		CreatedAt: time.Unix(u.CreatedAt, 0)}, nil
}

// ChangePassword re-seals the metadata key under the new metaKey, revokes
// every session of the account and returns a fresh one.
func (s *Service) ChangePassword(p *Principal, currentAuth []byte, c Credentials) (*Session, error) {
	if len(currentAuth) != KeySize || !validCreds(c) {
		return nil, ErrBadInput
	}
	if !s.attempts.Allow("uid:" + string(p.UserID)) {
		return nil, ErrThrottled
	}
	var epoch uint64
	err := s.st.UpdateUser(p.UserID, func(u *store.User) error {
		if !hmac.Equal(s.k.AuthHash(currentAuth), u.AuthHash) {
			return ErrAuth
		}
		priv, err := seal.Open(p.metaKey, u.MetaPrivSealed, metaAAD(u.ID))
		if err != nil {
			return ErrNoSession
		}
		defer clear(priv)
		sealed, err := seal.Seal(c.MetaKey, priv, metaAAD(u.ID))
		if err != nil {
			return err
		}
		u.Salt, u.Iterations, u.Keyset = c.Salt, c.Iterations, c.Keyset
		u.AuthHash = s.k.AuthHash(c.AuthKey)
		u.MetaPrivSealed = sealed
		u.Epoch++
		epoch = u.Epoch
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, err
	}
	_ = s.st.DeleteSession(p.sessionID)
	return s.newSession(p.UserID, epoch, c.MetaKey)
}

// RecoveryKeyset returns the keyset wrapped by the recovery code, after the
// caller proves knowledge of the code.
func (s *Service) RecoveryKeyset(login string, recAuth []byte) ([]byte, error) {
	if !ValidLogin(login) || len(recAuth) != KeySize {
		return nil, ErrBadInput
	}
	u, err := s.checkUser(login, func(u *store.User) []byte { return u.RecoveryHash }, s.k.RecoveryHash(recAuth))
	if err != nil {
		return nil, err
	}
	return u.RecoveryKeyset, nil
}

// Recover sets a new password and a new recovery code using the old recovery
// code. All existing sessions are revoked.
func (s *Service) Recover(login string, old Recovery, c Credentials, next Recovery) (*Session, error) {
	if !ValidLogin(login) || len(old.AuthKey) != KeySize || len(old.MetaKey) != KeySize ||
		!validCreds(c) || !validRecovery(next) {
		return nil, ErrBadInput
	}
	u, err := s.checkUser(login, func(u *store.User) []byte { return u.RecoveryHash }, s.k.RecoveryHash(old.AuthKey))
	if err != nil {
		return nil, err
	}
	var epoch uint64
	err = s.st.UpdateUser(u.ID, func(u *store.User) error {
		if !hmac.Equal(s.k.RecoveryHash(old.AuthKey), u.RecoveryHash) {
			return ErrAuth // the code was rotated concurrently
		}
		priv, err := seal.Open(old.MetaKey, u.RecoveryPrivSealed, recoveryAAD(u.ID))
		if err != nil {
			return ErrAuth
		}
		defer clear(priv)
		sealed, err := seal.Seal(c.MetaKey, priv, metaAAD(u.ID))
		if err != nil {
			return err
		}
		sealedRec, err := seal.Seal(next.MetaKey, priv, recoveryAAD(u.ID))
		if err != nil {
			return err
		}
		u.Salt, u.Iterations, u.Keyset = c.Salt, c.Iterations, c.Keyset
		u.AuthHash = s.k.AuthHash(c.AuthKey)
		u.MetaPrivSealed = sealed
		u.RecoveryHash = s.k.RecoveryHash(next.AuthKey)
		u.RecoveryPrivSealed = sealedRec
		u.RecoveryKeyset = next.Keyset
		u.Epoch++
		epoch = u.Epoch
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrAuth
	}
	if err != nil {
		return nil, err
	}
	return s.newSession(u.ID, epoch, c.MetaKey)
}

// CreateInvite issues a single-use invite code. Admins only.
func (s *Service) CreateInvite(p *Principal) ([]byte, time.Time, error) {
	if !p.Admin {
		return nil, time.Time{}, ErrForbidden
	}
	code := randBytes(KeySize)
	exp := s.now().Add(InviteLifetime)
	if err := s.st.PutInvite(s.k.InviteID(code), exp); err != nil {
		return nil, time.Time{}, err
	}
	return code, exp, nil
}

// DeleteAccount removes the account after re-checking the password.
func (s *Service) DeleteAccount(p *Principal, authKey []byte) error {
	if len(authKey) != KeySize {
		return ErrBadInput
	}
	if !s.attempts.Allow("uid:" + string(p.UserID)) {
		return ErrThrottled
	}
	u, priv, idx, err := s.open(p)
	if err != nil {
		return err
	}
	clear(priv)
	if !hmac.Equal(s.k.AuthHash(authKey), u.AuthHash) {
		return ErrAuth
	}
	if len(idx.Objects) > 0 {
		// SECURITY: objects are not implemented yet; refuse rather than leave
		// orphaned ciphertext behind.
		return ErrForbidden
	}
	if err := s.st.DeleteUser(u.ID); err != nil {
		return err
	}
	_ = s.st.DeleteSession(p.sessionID)
	return nil
}

// --- objects (access wiring for the next stage) ---

// Objects lists the IDs of objects the caller owns.
func (s *Service) Objects(p *Principal) ([][]byte, error) {
	_, priv, idx, err := s.open(p)
	if err != nil {
		return nil, err
	}
	clear(priv)
	return idx.Objects, nil
}

// Authorize decides whether the caller may perform act on the object.
// Unknown objects and denied access look the same to the caller.
func (s *Service) Authorize(p *Principal, objectID []byte, act access.Action) error {
	_, priv, idx, err := s.open(p)
	if err != nil {
		return err
	}
	clear(priv)
	g := access.Grant{Role: access.None}
	if slices.ContainsFunc(idx.Objects, func(o []byte) bool { return bytes.Equal(o, objectID) }) {
		g.Role = access.Owner
	}
	// Grants from other users (HPKE-sealed access records) come with sharing.
	obj, err := s.st.Object(objectID)
	if err != nil {
		return ErrNotFound
	}
	if err := access.Decide(g, act, access.Object{Immutable: obj.Immutable}, s.now()); err != nil {
		return ErrNotFound
	}
	return nil
}
