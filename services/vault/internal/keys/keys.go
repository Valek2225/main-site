// Package keys loads the server-side pepper and derives the server's subkeys.
package keys

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"

	"rima.su/vault/internal/seal"
)

const (
	pepperFile = "pepper"
	pepperSize = 32
)

// Keys are independent HKDF branches of the pepper.
type Keys struct {
	login    []byte
	auth     []byte
	fakeSalt []byte
	invite   []byte
}

// CheckPrivateDir fails unless dir exists, is a directory and is not accessible
// to group or others. Data must never be readable by other users of the host.
func CheckPrivateDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s has mode %o, want 0700", dir, fi.Mode().Perm())
	}
	return nil
}

// Load reads the pepper from dir, creating it on first start (mode 0400).
func Load(dir string) (*Keys, error) {
	if err := CheckPrivateDir(dir); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	pepper, err := readPepper(root)
	if errors.Is(err, fs.ErrNotExist) {
		pepper, err = createPepper(root)
	}
	if err != nil {
		return nil, err
	}
	defer clear(pepper)
	return derive(pepper), nil
}

func derive(pepper []byte) *Keys {
	return &Keys{
		login:    seal.Derive(pepper, "trebuchet vault login v1"),
		auth:     seal.Derive(pepper, "trebuchet vault auth v1"),
		fakeSalt: seal.Derive(pepper, "trebuchet vault fake-salt v1"),
		invite:   seal.Derive(pepper, "trebuchet vault invite v1"),
	}
}

// ForTest returns keys derived from a fixed pepper. Tests only.
func ForTest() *Keys { return derive(make([]byte, pepperSize)) }

func readPepper(root *os.Root) ([]byte, error) {
	f, err := root.Open(pepperFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("pepper is not a regular file")
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o277 != 0 {
		return nil, fmt.Errorf("pepper has mode %o, want 0400", fi.Mode().Perm())
	}
	b := make([]byte, pepperSize+1)
	n, err := io.ReadFull(f, b)
	if n != pepperSize || !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, errors.New("pepper has wrong size")
	}
	return b[:pepperSize], nil
}

func createPepper(root *os.Root) ([]byte, error) {
	// O_EXCL: never overwrite an existing pepper, it would lock everyone out.
	f, err := root.OpenFile(pepperFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return nil, err
	}
	p := make([]byte, pepperSize)
	_, _ = rand.Read(p)
	if _, err := f.Write(p); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return p, f.Close()
}

func mac(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// LoginID is the database key for a login. Logins are never stored in clear.
func (k *Keys) LoginID(login string) []byte { return mac(k.login, []byte(login)) }

// AuthHash is what the server stores instead of the client's authKey.
func (k *Keys) AuthHash(authKey []byte) []byte { return mac(k.auth, []byte("auth"), authKey) }

// RecoveryHash is AuthHash for the recovery code's auth branch.
func (k *Keys) RecoveryHash(recAuth []byte) []byte {
	return mac(k.auth, []byte("recovery"), recAuth)
}

// FakeSalt is returned for unknown logins so that prelogin does not reveal
// which logins exist. It is stable for a given login.
func (k *Keys) FakeSalt(loginID []byte) []byte { return mac(k.fakeSalt, loginID) }

// InviteID is the database key for an invite code.
func (k *Keys) InviteID(code []byte) []byte { return mac(k.invite, code) }
