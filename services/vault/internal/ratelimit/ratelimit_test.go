package ratelimit

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestBucket(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	l := New(60, time.Minute, 3, 10)
	l.Now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if !l.Allow("a") {
			t.Fatalf("request %d denied", i)
		}
	}
	if l.Allow("a") {
		t.Fatal("burst exceeded")
	}
	if !l.Allow("b") {
		t.Fatal("keys are not independent")
	}
	now = now.Add(time.Second)
	if !l.Allow("a") {
		t.Fatal("no refill")
	}
}

func TestFailClosedWhenFull(t *testing.T) {
	l := New(1, time.Hour, 1, 2)
	l.Allow("a")
	l.Allow("b")
	if l.Allow("c") {
		t.Fatal("limiter accepted a key beyond its capacity")
	}
}

func TestClientKey(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "[2001:db8:1:2:3:4:5:6]:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := ClientKey(r, false); got != "2001:db8:1:2::/64" {
		t.Fatalf("got %q", got)
	}
	if got := ClientKey(r, true); got != "203.0.113.9" {
		t.Fatalf("got %q", got)
	}
}
