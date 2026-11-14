// Package server is the HTTP layer of the vault service (app.rima.su).
package server

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"time"

	"rima.su/vault/internal/account"
	"rima.su/vault/internal/blobs"
	"rima.su/vault/internal/ratelimit"
	"rima.su/vault/web"
)

type Config struct {
	TrustProxy bool
}

type Server struct {
	cfg       Config
	acc       *account.Service
	blobs     *blobs.Store // used by object uploads in the next stage
	authLimit *ratelimit.Limiter
	apiLimit  *ratelimit.Limiter
	page      []byte
	static    map[string]staticFile
}

type staticFile struct {
	body        []byte
	contentType string
	etag        string // content hash: lets the browser revalidate without re-downloading
}

var contentTypes = map[string]string{
	".js":    "text/javascript; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".svg":   "image/svg+xml",
	".txt":   "text/plain; charset=utf-8",
	".woff2": "font/woff2",
}

// staticFiles is the complete allow-list of files under web/static that are
// served. Fonts: IBM Plex (SIL OFL 1.1), Cyrillic and Latin1 subsets only,
// from the official IBM/plex releases (plex-sans 1.1.0, plex-mono 2.5.0);
// byte-identical to the copies in the note service.
var staticFiles = []string{
	"app.js", "theme.js", "app.css", "favicon.svg", "words.txt", "blocklist.txt",
	"fonts/IBMPlexSans-Regular-Cyrillic.woff2", "fonts/IBMPlexSans-Regular-Latin1.woff2",
	"fonts/IBMPlexSans-Medium-Cyrillic.woff2", "fonts/IBMPlexSans-Medium-Latin1.woff2",
	"fonts/IBMPlexSans-SemiBold-Cyrillic.woff2", "fonts/IBMPlexSans-SemiBold-Latin1.woff2",
	"fonts/IBMPlexMono-Regular-Cyrillic.woff2", "fonts/IBMPlexMono-Regular-Latin1.woff2",
}

func New(cfg Config, acc *account.Service, bs *blobs.Store) (*Server, error) {
	s := &Server{
		cfg:       cfg,
		acc:       acc,
		blobs:     bs,
		authLimit: ratelimit.New(30, time.Minute, 10, 100_000),
		apiLimit:  ratelimit.New(300, time.Minute, 60, 100_000),
		static:    make(map[string]staticFile),
	}
	if err := s.loadStatic(); err != nil {
		return nil, err
	}
	if err := s.renderPage(); err != nil {
		return nil, err
	}
	return s, nil
}

// loadStatic reads an explicit allow-list of embedded files: no directory
// listing, no path traversal.
func (s *Server) loadStatic() error {
	for _, name := range staticFiles {
		body, err := fs.ReadFile(web.Static, "static/"+name)
		if err != nil {
			return fmt.Errorf("static %s: %w", name, err)
		}
		ct, ok := contentTypes[path.Ext(name)]
		if !ok {
			return fmt.Errorf("static %s: unknown content type", name)
		}
		sum := sha256.Sum256(body)
		s.static[name] = staticFile{
			body:        body,
			contentType: ct,
			etag:        `"` + base64.RawURLEncoding.EncodeToString(sum[:16]) + `"`,
		}
	}
	return nil
}

func sri(b []byte) string {
	sum := sha512.Sum384(b)
	return "sha384-" + base64.StdEncoding.EncodeToString(sum[:])
}

// renderPage renders the single HTML page once, with Subresource Integrity
// hashes for the script, the stylesheet and the data files the script fetches.
func (s *Server) renderPage() error {
	tpl, err := template.ParseFS(web.Templates, "templates/app.html")
	if err != nil {
		return err
	}
	data := map[string]string{
		"JSIntegrity":        sri(s.static["app.js"].body),
		"ThemeIntegrity":     sri(s.static["theme.js"].body),
		"CSSIntegrity":       sri(s.static["app.css"].body),
		"WordsIntegrity":     sri(s.static["words.txt"].body),
		"BlocklistIntegrity": sri(s.static["blocklist.txt"].body),
	}
	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "app.html", data); err != nil {
		return err
	}
	s.page = buf.Bytes()
	return nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(s.page)
	})
	mux.HandleFunc("GET /static/{name}", s.handleStatic)
	mux.HandleFunc("GET /static/fonts/{name}", s.handleStatic)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})

	auth, api := s.authLimit, s.apiLimit
	mux.HandleFunc("POST /api/v1/auth/prelogin", s.limited(auth, s.handlePrelogin))
	mux.HandleFunc("POST /api/v1/auth/login", s.limited(auth, s.handleLogin))
	mux.HandleFunc("POST /api/v1/auth/register", s.limited(auth, s.handleRegister))
	mux.HandleFunc("POST /api/v1/auth/recovery/keyset", s.limited(auth, s.handleRecoveryKeyset))
	mux.HandleFunc("POST /api/v1/auth/recovery/reset", s.limited(auth, s.handleRecoveryReset))
	mux.HandleFunc("POST /api/v1/auth/logout", s.limited(api, s.handleLogout))

	mux.HandleFunc("GET /api/v1/account", s.limited(api, s.authed(s.handleAccount)))
	mux.HandleFunc("POST /api/v1/account/password", s.limited(auth, s.authed(s.handlePassword)))
	mux.HandleFunc("POST /api/v1/account/delete", s.limited(auth, s.authed(s.handleDelete)))
	mux.HandleFunc("POST /api/v1/invites", s.limited(api, s.authed(s.handleInvite)))

	mux.HandleFunc("GET /api/v1/objects", s.limited(api, s.authed(s.handleListObjects)))
	mux.HandleFunc("POST /api/v1/objects", s.limited(api, s.authed(s.handleCreateObject)))
	mux.HandleFunc("GET /api/v1/objects/{id}", s.limited(api, s.authed(s.objectStub(actRead))))
	mux.HandleFunc("PUT /api/v1/objects/{id}", s.limited(api, s.authed(s.objectStub(actWrite))))
	mux.HandleFunc("DELETE /api/v1/objects/{id}", s.limited(api, s.authed(s.objectStub(actDelete))))
	mux.HandleFunc("POST /api/v1/objects/{id}/grants", s.limited(api, s.authed(s.objectStub(actShare))))

	// Rejects cross-site state-changing requests (CSRF) using
	// Sec-Fetch-Site / Origin; the session cookie is also SameSite=Strict.
	csrf := http.NewCrossOriginProtection()

	var h http.Handler = mux
	h = csrf.Handler(h)
	h = securityHeaders(h)
	h = accessLog(h)
	h = recoverPanics(h)
	return h
}

// CleanupLimiters forgets idle rate-limit buckets. Call it periodically.
func (s *Server) CleanupLimiters() {
	s.authLimit.Cleanup()
	s.apiLimit.Cleanup()
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	// The key is rebuilt from the matched route, never from the raw path, and
	// looked up in the allow-list map: nothing outside it can be served.
	key := r.PathValue("name")
	if r.Pattern == "GET /static/fonts/{name}" {
		key = "fonts/" + key
	}
	f, ok := s.static[key]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", f.contentType)
	w.Header().Set("ETag", f.etag)
	w.Header().Set("Cache-Control", "no-cache") // SRI hashes change with every release
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(f.body))
}
