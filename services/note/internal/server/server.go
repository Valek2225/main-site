// Package server is the HTTP layer of note.rima.su.
package server

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"time"

	"rima.su/note/internal/store"
	"rima.su/note/web"
)

type Config struct {
	TrustProxy bool
}

type Server struct {
	cfg         Config
	store       *store.Store
	createLimit *limiter
	takeLimit   *limiter
	pages       *template.Template // html/template: contextual escaping on every render
	pageData    map[string]string
	static      map[string]staticFile
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
	".woff2": "font/woff2",
}

// staticFiles is the complete allow-list of files under web/static that are
// served. Fonts: IBM Plex (SIL OFL 1.1), Cyrillic and Latin1 subsets only,
// taken from the official IBM/plex releases (plex-sans 1.1.0, plex-mono 2.5.0).
var staticFiles = []string{
	"note.js", "theme.js", "note.css", "favicon.svg",
	"fonts/IBMPlexSans-Regular-Cyrillic.woff2", "fonts/IBMPlexSans-Regular-Latin1.woff2",
	"fonts/IBMPlexSans-Medium-Cyrillic.woff2", "fonts/IBMPlexSans-Medium-Latin1.woff2",
	"fonts/IBMPlexSans-SemiBold-Cyrillic.woff2", "fonts/IBMPlexSans-SemiBold-Latin1.woff2",
	"fonts/IBMPlexMono-Regular-Cyrillic.woff2", "fonts/IBMPlexMono-Regular-Latin1.woff2",
}

func New(cfg Config, st *store.Store) (*Server, error) {
	s := &Server{
		cfg:         cfg,
		store:       st,
		createLimit: newLimiter(10, 10, 100_000),
		takeLimit:   newLimiter(60, 20, 100_000),
		static:      make(map[string]staticFile),
	}
	if err := s.loadStatic(); err != nil {
		return nil, err
	}
	if err := s.renderPages(); err != nil {
		return nil, err
	}
	return s, nil
}

// loadStatic reads an explicit allow-list of embedded files: no directory
// listing, no path traversal, no surprises.
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

// renderPages parses the templates and renders every page once at startup with
// Subresource Integrity hashes for every script and stylesheet, so a broken
// template fails the start instead of the first request.
func (s *Server) renderPages() error {
	tpl, err := template.ParseFS(web.Templates, "templates/*.html")
	if err != nil {
		return err
	}
	s.pageData = map[string]string{
		"JSIntegrity":    sri(s.static["note.js"].body),
		"ThemeIntegrity": sri(s.static["theme.js"].body),
		"CSSIntegrity":   sri(s.static["note.css"].body),
	}
	for _, name := range pageNames {
		if err := tpl.ExecuteTemplate(io.Discard, name, s.pageData); err != nil {
			return fmt.Errorf("render %s: %w", name, err)
		}
	}
	s.pages = tpl
	return nil
}

var pageNames = []string{"create.html", "read.html"}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", s.page("create.html"))
	mux.HandleFunc("GET /n/{id}", s.page("read.html"))
	mux.HandleFunc("GET /static/{name}", s.handleStatic)
	mux.HandleFunc("GET /static/fonts/{name}", s.handleStatic)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("POST /api/v1/notes", s.rateLimited(s.createLimit, s.handleCreate))
	mux.HandleFunc("POST /api/v1/notes/{id}/take", s.rateLimited(s.takeLimit, s.handleTake))

	// Rejects cross-site state-changing requests (CSRF) using
	// Sec-Fetch-Site / Origin headers.
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
	s.createLimit.cleanup()
	s.takeLimit.cleanup()
}

func (s *Server) page(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if name == "read.html" && !validID(r.PathValue("id")) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := s.pages.ExecuteTemplate(w, name, s.pageData); err != nil {
			slog.Error("render page failed", "page", name, "err", err)
		}
	}
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
	w.Header().Set("Cache-Control", "no-cache") // always revalidate: SRI hashes change with every release
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(f.body))
}
