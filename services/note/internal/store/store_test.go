package store

import (
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func put(t *testing.T, s *Store, token string, ttl time.Duration) string {
	t.Helper()
	id, err := s.Put([]byte("ciphertext"), sha256.Sum256([]byte(token)), ttl)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestTakeOnce(t *testing.T) {
	s := New(10, 1<<20)
	id := put(t, s, "tok", time.Hour)

	got, err := s.Take(id, []byte("tok"))
	if err != nil || string(got) != "ciphertext" {
		t.Fatalf("first take: %q %v", got, err)
	}
	if _, err := s.Take(id, []byte("tok")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second take must fail, got %v", err)
	}
	if s.Len() != 0 || s.bytes != 0 {
		t.Fatalf("store not empty: len=%d bytes=%d", s.Len(), s.bytes)
	}
}

func TestWrongTokenDoesNotBurn(t *testing.T) {
	s := New(10, 1<<20)
	id := put(t, s, "right", time.Hour)

	if _, err := s.Take(id, []byte("wrong")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong token must look like not found, got %v", err)
	}
	if _, err := s.Take(id, []byte("right")); err != nil {
		t.Fatalf("note must survive a wrong-token attempt: %v", err)
	}
}

func TestExpired(t *testing.T) {
	s := New(10, 1<<20)
	now := time.Now()
	s.now = func() time.Time { return now }
	id := put(t, s, "tok", time.Minute)

	now = now.Add(time.Minute)
	if _, err := s.Take(id, []byte("tok")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired note must not be returned, got %v", err)
	}
	if s.Len() != 0 {
		t.Fatal("expired note must be removed")
	}
}

func TestSweep(t *testing.T) {
	s := New(10, 1<<20)
	now := time.Now()
	s.now = func() time.Time { return now }
	put(t, s, "a", time.Minute)
	keep := put(t, s, "b", time.Hour)

	now = now.Add(2 * time.Minute)
	if n := s.Sweep(); n != 1 {
		t.Fatalf("swept %d, want 1", n)
	}
	if _, err := s.Take(keep, []byte("b")); err != nil {
		t.Fatal("live note was swept")
	}
}

func TestLimits(t *testing.T) {
	s := New(2, 1<<20)
	put(t, s, "a", time.Hour)
	put(t, s, "b", time.Hour)
	if _, err := s.Put([]byte("x"), [32]byte{}, time.Hour); !errors.Is(err, ErrFull) {
		t.Fatalf("count limit: %v", err)
	}

	s = New(10, 15)
	put(t, s, "a", time.Hour) // 10 bytes
	if _, err := s.Put([]byte("123456"), [32]byte{}, time.Hour); !errors.Is(err, ErrFull) {
		t.Fatalf("byte limit: %v", err)
	}
}

func TestUniqueIDs(t *testing.T) {
	s := New(10_000, 1<<30)
	seen := map[string]bool{}
	for i := 0; i < 10_000; i++ {
		id := put(t, s, "t", time.Hour)
		if len(id) != 22 || seen[id] {
			t.Fatalf("bad or duplicate id %q", id)
		}
		seen[id] = true
	}
}

// Many readers race for the same note: exactly one must win.
func TestConcurrentTakeExactlyOnce(t *testing.T) {
	for round := 0; round < 50; round++ {
		s := New(10, 1<<20)
		id := put(t, s, "tok", time.Hour)

		var wins atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 64; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if _, err := s.Take(id, []byte("tok")); err == nil {
					wins.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("round %d: %d readers got the note, want exactly 1", round, wins.Load())
		}
	}
}

func TestReturnedCopyIsIndependent(t *testing.T) {
	s := New(10, 1<<20)
	ct := []byte("secret-ct")
	id, _ := s.Put(ct, sha256.Sum256([]byte("t")), time.Hour)
	got, _ := s.Take(id, []byte("t"))
	if string(got) != "secret-ct" {
		t.Fatalf("got %q", got)
	}
	// The stored buffer must be wiped after removal.
	for _, b := range ct {
		if b != 0 {
			t.Fatal("stored ciphertext was not zeroed")
		}
	}
}
