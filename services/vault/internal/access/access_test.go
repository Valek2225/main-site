package access

import (
	"errors"
	"testing"
	"time"
)

func TestMatrix(t *testing.T) {
	now := time.Unix(1000, 0)
	mutable, immutable := Object{}, Object{Immutable: true}
	cases := []struct {
		role Role
		act  Action
		obj  Object
		ok   bool
	}{
		{Owner, Read, mutable, true},
		{Owner, Write, immutable, true},
		{Owner, Share, mutable, true},
		{Owner, Delete, mutable, true},
		{Edit, Read, mutable, true},
		{Edit, Write, mutable, true},
		{Edit, Write, immutable, false},
		{Edit, Share, mutable, false},
		{Edit, Delete, mutable, false},
		{View, Read, immutable, true},
		{View, Write, mutable, false},
		{View, Share, mutable, false},
		{View, Delete, mutable, false},
		{None, Read, mutable, false},
		{Role(200), Read, mutable, false},
		{Owner, Action(0), mutable, false},
		{Owner, Action(99), mutable, false},
	}
	for _, c := range cases {
		err := Decide(Grant{Role: c.role}, c.act, c.obj, now)
		if (err == nil) != c.ok {
			t.Errorf("%v %d immutable=%v: got %v", c.role, c.act, c.obj.Immutable, err)
		}
	}
}

func TestExpiry(t *testing.T) {
	exp := time.Unix(1000, 0)
	g := Grant{Role: View, ExpiresAt: exp}
	if err := Decide(g, Read, Object{}, exp.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := Decide(g, Read, Object{}, exp); !errors.Is(err, ErrExpired) {
		t.Fatalf("at expiry: %v", err)
	}
}

func TestCanGrant(t *testing.T) {
	if CanGrant(Edit, View, Object{}) {
		t.Fatal("editor can share")
	}
	if CanGrant(Owner, Edit, Object{Immutable: true}) {
		t.Fatal("edit granted on immutable object")
	}
	if CanGrant(Owner, Owner, Object{}) {
		t.Fatal("ownership granted")
	}
	if !CanGrant(Owner, View, Object{Immutable: true}) {
		t.Fatal("owner cannot share view")
	}
}

func TestParseRole(t *testing.T) {
	for _, s := range []string{"owner", "none", "", "VIEW", "view "} {
		if _, ok := ParseRole(s); ok {
			t.Errorf("accepted %q", s)
		}
	}
}
