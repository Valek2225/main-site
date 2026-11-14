// Package blobs stores opaque ciphertext files on disk.
//
// All file access goes through os.Root, so even a bug in ID validation cannot
// escape the blob directory. Files are 0600, the directory 0700.
package blobs

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
)

const MaxSize = 25<<20 + 1024 // 25 MiB of content plus envelope

var (
	ErrNotFound = errors.New("blob not found")
	ErrBadID    = errors.New("bad blob id")
	ErrTooLarge = errors.New("blob too large")
	ErrExists   = errors.New("blob exists")
)

type Store struct {
	root *os.Root
}

// Open opens (and creates, 0700) the blob directory.
func Open(dir string) (*Store, error) {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &Store{root: root}, nil
}

func (s *Store) Close() error { return s.root.Close() }

// NewID returns a random 128-bit blob ID.
func NewID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ValidID accepts exactly 22 base64url characters.
func ValidID(id string) bool {
	if len(id) != 22 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// name shards blobs into 64 subdirectories by the first ID character.
func name(id string) string { return path.Join(id[:1], id) }

// Put writes a new immutable blob. Blobs are never overwritten.
func (s *Store) Put(id string, data []byte) error {
	if !ValidID(id) {
		return ErrBadID
	}
	if len(data) > MaxSize {
		return ErrTooLarge
	}
	if err := s.root.Mkdir(id[:1], 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	if _, err := s.root.Lstat(name(id)); err == nil {
		return ErrExists
	}

	tmp := path.Join(id[:1], ".tmp-"+NewID())
	f, err := s.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = s.root.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := s.root.Rename(tmp, name(id)); err != nil {
		return err
	}
	ok = true
	return nil
}

// Get reads a whole blob.
func (s *Store) Get(id string) ([]byte, error) {
	if !ValidID(id) {
		return nil, ErrBadID
	}
	f, err := s.root.Open(name(id))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, ErrNotFound
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxSize {
		return nil, ErrTooLarge
	}
	return b, nil
}

// Delete removes a blob. Deleting a missing blob is not an error.
func (s *Store) Delete(id string) error {
	if !ValidID(id) {
		return ErrBadID
	}
	err := s.root.Remove(name(id))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
