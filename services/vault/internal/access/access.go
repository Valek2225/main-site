// Package access is the server-side access matrix for stored objects.
//
// It is one of two independent checks: a write must also carry a valid
// signature by the object's write key, which the server cannot forge.
package access

import (
	"errors"
	"time"
)

type Role uint8

const (
	None Role = iota
	View
	Edit
	Owner
)

type Action uint8

const (
	Read   Action = iota + 1 // download ciphertext
	Write                    // upload a new version
	Share                    // grant or revoke access
	Delete                   // delete the object
)

var (
	ErrDenied  = errors.New("access denied")
	ErrExpired = errors.New("access expired")
)

func (r Role) String() string {
	switch r {
	case View:
		return "view"
	case Edit:
		return "edit"
	case Owner:
		return "owner"
	}
	return "none"
}

// ParseRole accepts only roles that can be granted to another user.
func ParseRole(s string) (Role, bool) {
	switch s {
	case "view":
		return View, true
	case "edit":
		return Edit, true
	}
	return None, false
}

// Grant is one row of the ACL as seen at request time.
type Grant struct {
	Role      Role
	ExpiresAt time.Time // zero: no expiry
}

// Object holds the only object property the server knows in clear.
type Object struct {
	Immutable bool // HTML dashboards: only the owner may write
}

func allows(r Role, a Action, obj Object) bool {
	switch r {
	case Owner:
		return a == Read || a == Write || a == Share || a == Delete
	case Edit:
		return a == Read || (a == Write && !obj.Immutable)
	case View:
		return a == Read
	}
	return false
}

// Decide is the single place where object access is decided. The server's
// clock is the only clock that counts for expiry.
func Decide(g Grant, a Action, obj Object, now time.Time) error {
	if !allows(g.Role, a, obj) {
		return ErrDenied
	}
	if !g.ExpiresAt.IsZero() && !now.Before(g.ExpiresAt) {
		return ErrExpired
	}
	return nil
}

// CanGrant reports whether granter may give role to someone else.
func CanGrant(granter Role, role Role, obj Object) bool {
	if granter != Owner {
		return false
	}
	switch role {
	case View:
		return true
	case Edit:
		return !obj.Immutable
	}
	return false
}
