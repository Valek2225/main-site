package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"sync"
	"time"
)

// limiter is a per-client token bucket.
//
// Client IPs are never stored as-is: the key is an HMAC of the IP under a
// random key that lives only in this process, so even a memory dump does not
// give a list of visitors' addresses.
type limiter struct {
	mu         sync.Mutex
	buckets    map[[16]byte]*bucket
	rate       float64 // tokens per second
	burst      float64
	maxClients int
	secret     [32]byte
	now        func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(perMinute, burst, maxClients int) *limiter {
	l := &limiter{
		buckets:    make(map[[16]byte]*bucket),
		rate:       float64(perMinute) / 60,
		burst:      float64(burst),
		maxClients: maxClients,
		now:        time.Now,
	}
	_, _ = rand.Read(l.secret[:])
	return l
}

func (l *limiter) key(ip string) [16]byte {
	m := hmac.New(sha256.New, l.secret[:])
	m.Write([]byte(ip))
	var k [16]byte
	copy(k[:], m.Sum(nil))
	return k
}

func (l *limiter) allow(ip string) bool {
	k := l.key(ip)
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[k]
	if !ok {
		if len(l.buckets) >= l.maxClients {
			l.cleanupLocked(now)
			if len(l.buckets) >= l.maxClients {
				return false // fail closed under a flood of distinct clients
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

// cleanup drops buckets that have refilled completely (idle clients).
func (l *limiter) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cleanupLocked(l.now())
}

func (l *limiter) cleanupLocked(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
}
