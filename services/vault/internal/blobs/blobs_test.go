package blobs

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func open(t *testing.T) (*Store, string) {
	d := filepath.Join(t.TempDir(), "blobs")
	s, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, d
}

func TestPutGetDelete(t *testing.T) {
	s, d := open(t)
	id := NewID()
	if err := s.Put(id, []byte("ct")); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(id, []byte("other")); !errors.Is(err, ErrExists) {
		t.Fatalf("overwrite: %v", err)
	}
	b, err := s.Get(id)
	if err != nil || string(b) != "ct" {
		t.Fatalf("get: %v %q", err, b)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(filepath.Join(d, id[:1], id))
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("blob mode %o", fi.Mode().Perm())
		}
		fi, _ = os.Stat(d)
		if fi.Mode().Perm() != 0o700 {
			t.Fatalf("dir mode %o", fi.Mode().Perm())
		}
	}
	if err := s.Delete(id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}

func TestRejectsTraversal(t *testing.T) {
	s, _ := open(t)
	for _, id := range []string{"../../../../etc/passwd", "..", "", "a/b", "AAAAAAAAAAAAAAAAAAAA.."} {
		if err := s.Put(id, nil); !errors.Is(err, ErrBadID) {
			t.Errorf("put %q: %v", id, err)
		}
		if _, err := s.Get(id); !errors.Is(err, ErrBadID) {
			t.Errorf("get %q: %v", id, err)
		}
	}
}

func TestTooLarge(t *testing.T) {
	s, _ := open(t)
	if err := s.Put(NewID(), make([]byte, MaxSize+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
}

func FuzzValidID(f *testing.F) {
	f.Add("AAAAAAAAAAAAAAAAAAAAAA")
	f.Add("../AAAAAAAAAAAAAAAAAAAA")
	f.Fuzz(func(t *testing.T, id string) {
		if !ValidID(id) {
			return
		}
		if len(id) != 22 || filepath.Base(id) != id || id == "." || id == ".." {
			t.Fatalf("accepted %q", id)
		}
	})
}
