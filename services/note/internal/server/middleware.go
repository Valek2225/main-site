package server

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

const contentSecurityPolicy = "default-src 'none'; " +
	"script-src 'self'; " +
	"style-src 'self'; " +
	"img-src 'self'; " +
	"connect-src 'self'; " +
	"base-uri 'none'; " +
	"form-action 'none'; " +
	"frame-ancestors 'none'; " +
	"require-trusted-types-for 'script'; " +
	"trusted-types 'none'; " +
	"upgrade-insecure-requests"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cross-Origin-Embedder-Policy", "require-corp")
		h.Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "+
			"magnetometer=(), microphone=(), payment=(), usb=(), browsing-topics=()")
		h.Set("X-Robots-Tag", "noindex, nofollow, noarchive")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// recoverPanics turns a panic into a generic 500 without leaking details.
func recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				slog.Error("panic in handler", "pattern", r.Pattern)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// accessLog logs only the route pattern, never the path (it contains note IDs),
// query, IP, user agent or body.
func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		pattern := r.Pattern
		if pattern == "" {
			pattern = "(unmatched)"
		}
		slog.Info("request", "pattern", pattern, "status", rec.status,
			"ms", time.Since(start).Milliseconds())
	})
}

func (s *Server) rateLimited(l *limiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(s.clientIP(r)) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "too many requests")
			return
		}
		next(w, r)
	}
}

// clientIP returns the caller's address. X-Forwarded-For is honoured only when
// the service runs behind our own Caddy, which overwrites the header with the
// real client address (it is never trusted from the internet directly).
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
				return limitKey(ip)
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil {
		return limitKey(ip)
	}
	return host
}

// limitKey groups IPv6 clients by /64: one user usually owns a whole /64,
// so per-address limits would be trivial to bypass.
func limitKey(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
