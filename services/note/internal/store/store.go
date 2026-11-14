// Package store keeps encrypted notes in process memory only.
//
// Nothing is ever written to disk: a restart wipes every note, which is part
// of the service's guarantee. The server never sees plaintext or keys, only
// ciphertext and a SHA-256 hash of the read token derived from the key.
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

const (
	IDBytes        = 16 // 128 bits
	TokenHashBytes = sha256.Size
)

var (
	// ErrNotFound covers "never existed", "already read", "expired" and
	// "wrong token" alike, so callers cannot tell them apart.
	ErrNotFound = errors.New("note not found")
	ErrFull     = errors.New("store is full")
)

type note struct {
	ciphertext []byte
	tokenHash  [TokenHashBytes]byte
	expires    time.Time
}

type Store struct {
	mu       sync.Mutex
	notes    map[string]*note
	bytes    int
	maxNotes int
	maxBytes int
	now      func() time.Time
}

func New(maxNotes, maxBytes int) *Store {
	return &Store{
		notes:    make(map[string]*note),
		maxNotes: maxNotes,
		maxBytes: maxBytes,
		now:      time.Now,
	}
}

// Put stores ciphertext and returns a fresh random ID.
// The caller must not reuse ciphertext afterwards: the store owns it.
func (s *Store) Put(ciphertext []byte, tokenHash [TokenHashBytes]byte, ttl time.Duration) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.notes) >= s.maxNotes || s.bytes+len(ciphertext) > s.maxBytes {
		return "", ErrFull
	}

	for {
		var raw [IDBytes]byte
		// crypto/rand.Read never returns an error since Go 1.24 (it crashes instead).
		_, _ = rand.Read(raw[:])
		id := base64.RawURLEncoding.EncodeToString(raw[:])
		if _, taken := s.notes[id]; taken {
			continue // practically impossible with 128 bits, but never overwrite
		}
		s.notes[id] = &note{
			ciphertext: ciphertext,
			tokenHash:  tokenHash,
			expires:    s.now().Add(ttl),
		}
		s.bytes += len(ciphertext)
		return id, nil
	}
}

// Take atomically returns and deletes the note if the token matches.
// A wrong token does NOT delete the note, so someone who only knows the ID
// cannot burn it.
func (s *Store) Take(id string, token []byte) ([]byte, error) {
	got := sha256.Sum256(token)

	s.mu.Lock()
	defer s.mu.Unlock()

	n, ok := s.notes[id]
	if !ok {
		return nil, ErrNotFound
	}
	if !s.now().Before(n.expires) {
		s.removeLocked(id, n)
		return nil, ErrNotFound
	}
	if subtle.ConstantTimeCompare(got[:], n.tokenHash[:]) != 1 {
		return nil, ErrNotFound
	}

	out := make([]byte, len(n.ciphertext))
	copy(out, n.ciphertext)
	s.removeLocked(id, n)
	return out, nil
}

// Sweep removes expired notes. Call it periodically.
func (s *Store) Sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	removed := 0
	for id, n := range s.notes {
		if !now.Before(n.expires) {
			s.removeLocked(id, n)
			removed++
		}
	}
	return removed
}

// Wipe removes every note (used on shutdown).
func (s *Store) Wipe() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, n := range s.notes {
		s.removeLocked(id, n)
	}
}

func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.notes)
}

func (s *Store) removeLocked(id string, n *note) {
	// Best-effort zeroing: Go's GC may have copied the data, but we don't
	// leave the buffer around any longer than needed.
	clear(n.ciphertext)
	clear(n.tokenHash[:])
	s.bytes -= len(n.ciphertext)
	delete(s.notes, id)
}
