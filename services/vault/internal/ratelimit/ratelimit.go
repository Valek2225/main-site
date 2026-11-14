// Package ratelimit is a per-key token bucket.
//
// Keys (client IPs, login IDs) are never stored as-is: the map key is an HMAC
// under a random secret that lives only in this process.
package ratelimit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Limiter struct {
	mu      sync.Mutex
	buckets map[[16]byte]*bucket
	rate    float64 // tokens per second
	burst   float64
	maxKeys int
	secret  [32]byte
	Now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New allows `burst` events at once and refills `count` events per `per`.
func New(count int, per time.Duration, burst, maxKeys int) *Limiter {
	l := &Limiter{
		buckets: make(map[[16]byte]*bucket),
		rate:    float64(count) / per.Seconds(),
		burst:   float64(burst),
		maxKeys: maxKeys,
		Now:     time.Now,
	}
	_, _ = rand.Read(l.secret[:])
	return l
}

func (l *Limiter) key(k string) [16]byte {
	m := hmac.New(sha256.New, l.secret[:])
	m.Write([]byte(k))
	var out [16]byte
	copy(out[:], m.Sum(nil))
	return out
}

// Allow consumes one token for key and reports whether it was available.
func (l *Limiter) Allow(key string) bool {
	k := l.key(key)
	now := l.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[k]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			l.cleanupLocked(now)
			if len(l.buckets) >= l.maxKeys {
				return false // fail closed under a flood of distinct keys
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[k] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Cleanup forgets keys whose buckets have refilled completely.
func (l *Limiter) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cleanupLocked(l.Now())
}

func (l *Limiter) cleanupLocked(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
}

// ClientKey returns the caller's address for rate limiting. X-Forwarded-For is
// honoured only behind our own Caddy, which overwrites it with the real client
// address; it is never trusted from the internet directly.
func ClientKey(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
				return group(ip)
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil {
		return group(ip)
	}
	return host
}

// group puts all IPv6 addresses of one /64 into one bucket: a single user
// usually owns the whole /64.
func group(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
