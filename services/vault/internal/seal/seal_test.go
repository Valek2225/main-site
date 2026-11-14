package seal

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSealOpen(t *testing.T) {
	k := make([]byte, KeySize)
	_, _ = rand.Read(k)
	ct, err := Seal(k, []byte("secret"), []byte("ctx"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Open(k, ct, []byte("ctx"))
	if err != nil || string(pt) != "secret" {
		t.Fatalf("open: %v %q", err, pt)
	}
	if _, err := Open(k, ct, []byte("other")); err == nil {
		t.Fatal("opened with wrong aad")
	}
	bad := bytes.Clone(k)
	bad[0] ^= 1
	if _, err := Open(bad, ct, []byte("ctx")); err == nil {
		t.Fatal("opened with wrong key")
	}
	ct[len(ct)-1] ^= 1
	if _, err := Open(k, ct, []byte("ctx")); err == nil {
		t.Fatal("opened tampered ciphertext")
	}
	if _, err := Open(k, ct[:5], nil); err == nil {
		t.Fatal("opened short ciphertext")
	}
	if _, err := Seal(k[:16], nil, nil); err == nil {
		t.Fatal("accepted short key")
	}
}

func TestNoncesDiffer(t *testing.T) {
	k := make([]byte, KeySize)
	a, _ := Seal(k, []byte("x"), nil)
	b, _ := Seal(k, []byte("x"), nil)
	if bytes.Equal(a, b) {
		t.Fatal("same ciphertext twice: nonce reuse")
	}
}

func TestDeriveIndependent(t *testing.T) {
	s := make([]byte, 32)
	if bytes.Equal(Derive(s, "a"), Derive(s, "b")) {
		t.Fatal("different labels gave the same key")
	}
	if !bytes.Equal(Derive(s, "a"), Derive(s, "a")) {
		t.Fatal("derive is not deterministic")
	}
}

func TestAADUnambiguous(t *testing.T) {
	if bytes.Equal(AAD("x", []byte("ab"), []byte("c")), AAD("x", []byte("a"), []byte("bc"))) {
		t.Fatal("aad is ambiguous")
	}
}
