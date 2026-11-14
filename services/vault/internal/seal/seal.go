// Package seal wraps AES-256-GCM and HKDF-SHA-256 from the standard library.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const (
	KeySize   = 32
	nonceSize = 12
	Overhead  = nonceSize + 16 // random nonce + tag
	maxPart   = 0xFFFF
)

var ErrOpen = errors.New("seal: cannot open")

func aead(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("seal: bad key size")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// Seal encrypts plaintext under key; aad binds the ciphertext to its context.
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	g, err := aead(key)
	if err != nil {
		return nil, err
	}
	// A fresh random 96-bit nonce for every message, stored in front of it.
	out := make([]byte, nonceSize, nonceSize+len(plaintext)+g.Overhead())
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return g.Seal(out, out, plaintext, aad), nil
}

// Open decrypts a value produced by Seal with the same key and aad.
func Open(key, sealed, aad []byte) ([]byte, error) {
	g, err := aead(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < Overhead {
		return nil, ErrOpen
	}
	pt, err := g.Open(nil, sealed[:nonceSize], sealed[nonceSize:], aad)
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

// Derive returns a 32-byte HKDF-SHA-256 subkey of secret for the given purpose.
func Derive(secret []byte, info string) []byte {
	k, err := hkdf.Key(sha256.New, secret, nil, info, KeySize)
	if err != nil {
		panic("seal: hkdf: " + err.Error()) // only possible for absurd lengths
	}
	return k
}

// AAD joins a context label and binary parts into associated data. Parts are
// length-prefixed, so different splits never produce the same bytes.
func AAD(label string, parts ...[]byte) []byte {
	n := len(label) + 1
	for _, p := range parts {
		n += 2 + len(p)
	}
	out := make([]byte, 0, n)
	out = append(out, label...)
	out = append(out, 0)
	for _, p := range parts {
		n := len(p)
		if n > maxPart {
			panic("seal: aad part too long") // callers pass fixed-size IDs and keys
		}
		out = binary.BigEndian.AppendUint16(out, uint16(n))
		out = append(out, p...)
	}
	return out
}
