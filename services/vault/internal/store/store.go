// Package store persists vault records in a single bbolt file.
//
// Values that reveal relations between users are sealed by the caller before
// they reach this package; the store only sees opaque bytes for them.
package store

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

const schemaVersion = 1

var (
	bMeta     = []byte("meta")
	bUsers    = []byte("users")
	bLogins   = []byte("logins")
	bSessions = []byte("sessions")
	bIndex    = []byte("index")
	bInvites  = []byte("invites")
	bObjects  = []byte("objects")
	bVersions = []byte("versions")
	bAccess   = []byte("access")
	bInbox    = []byte("inbox")
	bLinks    = []byte("links")

	allBuckets = [][]byte{bMeta, bUsers, bLogins, bSessions, bIndex, bInvites,
		bObjects, bVersions, bAccess, bInbox, bLinks}

	kSchema       = []byte("schema")
	kBootstrapped = []byte("bootstrapped")
)

var (
	ErrNotFound    = errors.New("not found")
	ErrLoginTaken  = errors.New("login taken")
	ErrInvite      = errors.New("invalid invite")
	ErrUnsupported = errors.New("database schema is newer than this binary")
)

// User is the per-account record. Byte fields marked E2EE are opaque to the
// server; *Sealed fields can be opened only with key material from the user.
type User struct {
	V          int    `json:"v"`
	ID         []byte `json:"id"`
	LoginID    []byte `json:"login_id"` // HMAC(pepper, login)
	Salt       []byte `json:"salt"`
	Iterations int    `json:"iterations"`
	AuthHash   []byte `json:"auth_hash"` // HMAC(pepper, authKey)

	MetaPub            []byte `json:"meta_pub"`
	MetaPrivSealed     []byte `json:"meta_priv_sealed"`     // under metaKey
	RecoveryHash       []byte `json:"recovery_hash"`        // HMAC(pepper, recoveryAuth)
	RecoveryPrivSealed []byte `json:"recovery_priv_sealed"` // under recoveryMetaKey

	IdentityPub    []byte `json:"identity_pub"`    // Ed25519
	ExchangePub    []byte `json:"exchange_pub"`    // X25519
	Keyset         []byte `json:"keyset"`          // E2EE, wrapped by wrapKey
	RecoveryKeyset []byte `json:"recovery_keyset"` // E2EE, wrapped by recovery key

	Epoch     uint64 `json:"epoch"` // bumped to revoke all sessions
	Admin     bool   `json:"admin"`
	CreatedAt int64  `json:"created_at"`
}

// Object is the clear part of an object record.
type Object struct {
	V         int    `json:"v"`
	Immutable bool   `json:"immutable"`
	Version   uint64 `json:"version"`
}

type Store struct {
	db  *bolt.DB
	now func() time.Time
}

// Open opens or creates the database file (mode 0600).
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, now: time.Now}
	if err := s.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) init() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, b := range allBuckets {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		meta := tx.Bucket(bMeta)
		v := meta.Get(kSchema)
		if v == nil {
			return meta.Put(kSchema, u64(schemaVersion))
		}
		if len(v) != 8 {
			return errors.New("corrupt schema version")
		}
		switch got := binary.BigEndian.Uint64(v); {
		case got > schemaVersion:
			return ErrUnsupported // fail closed: never touch data we do not understand
		case got < schemaVersion:
			return fmt.Errorf("no migration from schema %d", got)
		}
		return nil
	})
}

func u64(n uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, n)
	return b
}

// encTime stores a Unix time; negative times are clamped to 0.
func encTime(t int64) []byte {
	if t < 0 {
		return u64(0)
	}
	return u64(uint64(t))
}

// decTime reads a time written by encTime. Malformed values report ok=false,
// and callers treat them as already expired (fail closed).
func decTime(b []byte) (int64, bool) {
	if len(b) < 8 {
		return 0, false
	}
	v := binary.BigEndian.Uint64(b[:8])
	if v > math.MaxInt64 {
		return 0, false
	}
	return int64(v), true
}

// alive reports whether a value starting with an expiry time is still valid.
func alive(v []byte, now int64) bool {
	t, ok := decTime(v)
	return ok && t > now
}

func getJSON(b *bolt.Bucket, key []byte, dst any) error {
	v := b.Get(key)
	if v == nil {
		return ErrNotFound
	}
	return json.Unmarshal(v, dst)
}

func putJSON(b *bolt.Bucket, key []byte, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Put(key, data)
}

// Registration describes how an account is admitted.
type Registration struct {
	InviteID  []byte // HMAC of a regular invite code, or nil
	Bootstrap bool   // first admin; allowed exactly once
}

// CreateUser atomically consumes the invite and creates the account with its
// sealed index. If the login is taken, nothing changes and the invite stays.
func (s *Store) CreateUser(u *User, reg Registration, sealedIndex []byte) error {
	now := s.now().Unix()
	return s.db.Update(func(tx *bolt.Tx) error {
		meta, invites := tx.Bucket(bMeta), tx.Bucket(bInvites)
		switch {
		case reg.Bootstrap:
			if meta.Get(kBootstrapped) != nil {
				return ErrInvite
			}
			if err := meta.Put(kBootstrapped, encTime(now)); err != nil {
				return err
			}
			u.Admin = true
		case reg.InviteID != nil:
			v := invites.Get(reg.InviteID)
			if len(v) != 8 || !alive(v, now) {
				return ErrInvite
			}
			if err := invites.Delete(reg.InviteID); err != nil {
				return err
			}
		default:
			return ErrInvite
		}

		logins, users := tx.Bucket(bLogins), tx.Bucket(bUsers)
		if logins.Get(u.LoginID) != nil {
			return ErrLoginTaken
		}
		if users.Get(u.ID) != nil {
			return errors.New("user id collision")
		}
		u.V = 1
		u.CreatedAt = now
		if err := putJSON(users, u.ID, u); err != nil {
			return err
		}
		if err := logins.Put(u.LoginID, u.ID); err != nil {
			return err
		}
		return tx.Bucket(bIndex).Put(u.ID, sealedIndex)
	})
}

// Bootstrapped reports whether the first admin has been created.
func (s *Store) Bootstrapped() (bool, error) {
	var ok bool
	err := s.db.View(func(tx *bolt.Tx) error {
		ok = tx.Bucket(bMeta).Get(kBootstrapped) != nil
		return nil
	})
	return ok, err
}

func (s *Store) UserByLogin(loginID []byte) (*User, error) {
	var u User
	err := s.db.View(func(tx *bolt.Tx) error {
		id := tx.Bucket(bLogins).Get(loginID)
		if id == nil {
			return ErrNotFound
		}
		return getJSON(tx.Bucket(bUsers), id, &u)
	})
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) UserByID(id []byte) (*User, error) {
	var u User
	err := s.db.View(func(tx *bolt.Tx) error { return getJSON(tx.Bucket(bUsers), id, &u) })
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// UpdateUser runs read-modify-write on a user in one transaction, so two
// concurrent changes (e.g. password change and recovery) cannot interleave.
func (s *Store) UpdateUser(id []byte, fn func(*User) error) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		users := tx.Bucket(bUsers)
		var u User
		if err := getJSON(users, id, &u); err != nil {
			return err
		}
		if err := fn(&u); err != nil {
			return err
		}
		if !bytes.Equal(u.ID, id) {
			return errors.New("user id changed")
		}
		return putJSON(users, id, &u)
	})
}

// DeleteUser removes the account, its login mapping and its index.
func (s *Store) DeleteUser(id []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		users := tx.Bucket(bUsers)
		var u User
		if err := getJSON(users, id, &u); err != nil {
			return err
		}
		if err := tx.Bucket(bLogins).Delete(u.LoginID); err != nil {
			return err
		}
		if err := tx.Bucket(bIndex).Delete(id); err != nil {
			return err
		}
		return users.Delete(id)
	})
}

// --- personal index (sealed by the caller) ---

func (s *Store) Index(userID []byte) ([]byte, error) {
	var out []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bIndex).Get(userID)
		if v == nil {
			return ErrNotFound
		}
		out = bytes.Clone(v)
		return nil
	})
	return out, err
}

func (s *Store) PutIndex(userID, sealed []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(bUsers).Get(userID) == nil {
			return ErrNotFound
		}
		return tx.Bucket(bIndex).Put(userID, sealed)
	})
}

// --- sessions: key = derived from the token, value = expiry || sealed blob ---

func (s *Store) PutSession(id []byte, expires time.Time, sealed []byte) error {
	v := append(encTime(expires.Unix()), sealed...)
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bSessions).Put(id, v) })
}

// Session returns the sealed session if it exists and has not expired.
func (s *Store) Session(id []byte) ([]byte, error) {
	var out []byte
	now := s.now().Unix()
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bSessions).Get(id)
		if !alive(v, now) {
			return ErrNotFound
		}
		out = bytes.Clone(v[8:])
		return nil
	})
	return out, err
}

func (s *Store) DeleteSession(id []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bSessions).Delete(id) })
}

// --- invites: key = HMAC(pepper, code), value = expiry ---

func (s *Store) PutInvite(id []byte, expires time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bInvites).Put(id, encTime(expires.Unix()))
	})
}

// --- objects (stubs for the next stage) ---

func (s *Store) Object(id []byte) (*Object, error) {
	var o Object
	err := s.db.View(func(tx *bolt.Tx) error { return getJSON(tx.Bucket(bObjects), id, &o) })
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// Sweep deletes expired sessions and invites.
func (s *Store) Sweep() (int, error) {
	now := s.now().Unix()
	n := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bSessions, bInvites} {
			c := tx.Bucket(name).Cursor()
			for k, v := c.First(); k != nil; {
				if !alive(v, now) {
					if err := c.Delete(); err != nil {
						return err
					}
					n++
					k, v = c.Seek(k)
					continue
				}
				k, v = c.Next()
			}
		}
		return nil
	})
	return n, err
}

// Snapshot writes a consistent copy of the database to dir/vault.db (0600)
// for the host's encrypted backup job.
func (s *Store) Snapshot(dir string) error {
	tmp, err := os.CreateTemp(dir, ".vault-*.db")
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if err := s.db.View(func(tx *bolt.Tx) error {
		_, err := tx.WriteTo(tmp)
		return err
	}); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, "vault.db")); err != nil {
		return err
	}
	ok = true
	return nil
}
