package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"rima.su/note/internal/store"
)

// newTestServer has rate limits lifted so that functional tests don't hit them.
func newTestServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	s := newRealLimitsServer(t)
	s.createLimit = newLimiter(1<<30, 1<<30, 1<<20)
	s.takeLimit = newLimiter(1<<30, 1<<30, 1<<20)
	return s, s.Handler()
}

func newRealLimitsServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(Config{}, store.New(1000, 64<<20))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func do(h http.Handler, method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func validCreate(token []byte) string {
	ct := make([]byte, nonceBytes+512+tagBytes)
	th := sha256.Sum256(token)
	b, _ := json.Marshal(createRequest{
		Ciphertext: b64.EncodeToString(ct),
		TokenHash:  b64.EncodeToString(th[:]),
		TTL:        3600,
	})
	return string(b)
}

func create(t *testing.T, h http.Handler, token []byte) string {
	t.Helper()
	rec := do(h, "POST", "/api/v1/notes", validCreate(token), nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var resp createResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || !validID(resp.ID) {
		t.Fatalf("bad create response %s", rec.Body)
	}
	return resp.ID
}

func take(h http.Handler, id string, token []byte) *httptest.ResponseRecorder {
	body, _ := json.Marshal(takeRequest{Token: b64.EncodeToString(token)})
	return do(h, "POST", "/api/v1/notes/"+id+"/take", string(body), nil)
}

func TestCreateAndTakeOnce(t *testing.T) {
	_, h := newTestServer(t)
	token := bytes.Repeat([]byte{7}, tokenBytes)
	id := create(t, h, token)

	if rec := take(h, id, token); rec.Code != http.StatusOK {
		t.Fatalf("first take: %d", rec.Code)
	}
	if rec := take(h, id, token); rec.Code != http.StatusNotFound {
		t.Fatalf("second take: %d, want 404", rec.Code)
	}
}

func TestWrongTokenIs404AndKeepsNote(t *testing.T) {
	_, h := newTestServer(t)
	token := bytes.Repeat([]byte{1}, tokenBytes)
	id := create(t, h, token)

	if rec := take(h, id, bytes.Repeat([]byte{2}, tokenBytes)); rec.Code != http.StatusNotFound {
		t.Fatalf("wrong token: %d", rec.Code)
	}
	if rec := take(h, id, token); rec.Code != http.StatusOK {
		t.Fatalf("note burned by wrong token: %d", rec.Code)
	}
}

func TestGetNeverReturnsNote(t *testing.T) {
	_, h := newTestServer(t)
	token := bytes.Repeat([]byte{3}, tokenBytes)
	id := create(t, h, token)

	// Link-preview bots use GET: they must only get the static page.
	if rec := do(h, "GET", "/api/v1/notes/"+id+"/take", "", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET take: %d, want 405", rec.Code)
	}
	if rec := do(h, "GET", "/n/"+id, "", nil); rec.Code != http.StatusOK {
		t.Fatalf("read page: %d", rec.Code)
	}
	if rec := take(h, id, token); rec.Code != http.StatusOK {
		t.Fatalf("note must survive GETs: %d", rec.Code)
	}
}

func TestCreateValidation(t *testing.T) {
	_, h := newTestServer(t)
	th := sha256.Sum256([]byte("x"))
	goodTH := b64.EncodeToString(th[:])
	ct := func(n int) string { return b64.EncodeToString(make([]byte, n)) }

	cases := map[string]struct {
		body string
		ct   string
		want int
	}{
		"unpadded size":   {`{"ciphertext":"` + ct(100) + `","token_hash":"` + goodTH + `","ttl":3600}`, "", 400},
		"short":           {`{"ciphertext":"` + ct(5) + `","token_hash":"` + goodTH + `","ttl":3600}`, "", 400},
		"bad ttl":         {`{"ciphertext":"` + ct(540) + `","token_hash":"` + goodTH + `","ttl":5}`, "", 400},
		"short hash":      {`{"ciphertext":"` + ct(540) + `","token_hash":"AAAA","ttl":3600}`, "", 400},
		"padded b64":      {`{"ciphertext":"` + ct(540) + `==","token_hash":"` + goodTH + `","ttl":3600}`, "", 400},
		"std b64":         {`{"ciphertext":"++//","token_hash":"` + goodTH + `","ttl":3600}`, "", 400},
		"unknown field":   {`{"ciphertext":"` + ct(540) + `","token_hash":"` + goodTH + `","ttl":3600,"x":1}`, "", 400},
		"two values":      {`{"ciphertext":"` + ct(540) + `","token_hash":"` + goodTH + `","ttl":3600}{}`, "", 400},
		"not json":        {`hello`, "", 400},
		"wrong type":      {`{"ttl":"3600"}`, "", 400},
		"form content":    {validCreate([]byte("x")), "application/x-www-form-urlencoded", 415},
		"text content":    {validCreate([]byte("x")), "text/plain", 415},
		"too large":       {`{"ciphertext":"` + strings.Repeat("A", 200<<10) + `"}`, "", 413},
		"json with chset": {validCreate([]byte("x")), "application/json; charset=utf-8", 201},
	}
	for name, c := range cases {
		hdr := map[string]string{}
		if c.ct != "" {
			hdr["Content-Type"] = c.ct
		}
		if rec := do(h, "POST", "/api/v1/notes", c.body, hdr); rec.Code != c.want {
			t.Errorf("%s: got %d, want %d (%s)", name, rec.Code, c.want, rec.Body)
		}
	}
}

func TestTakeValidation(t *testing.T) {
	_, h := newTestServer(t)
	good := strings.Repeat("A", 22)
	cases := map[string]struct {
		path, body string
		want       int
	}{
		"short id":      {"/api/v1/notes/abc/take", `{"token":""}`, 404},
		"bad id chars":  {"/api/v1/notes/" + strings.Repeat("!", 22) + "/take", `{"token":""}`, 404},
		"short token":   {"/api/v1/notes/" + good + "/take", `{"token":"AAAA"}`, 400},
		"unknown id":    {"/api/v1/notes/" + good + "/take", `{"token":"` + b64.EncodeToString(make([]byte, 32)) + `"}`, 404},
		"unknown field": {"/api/v1/notes/" + good + "/take", `{"token":"x","id":"y"}`, 400},
	}
	for name, c := range cases {
		if rec := do(h, "POST", c.path, c.body, nil); rec.Code != c.want {
			t.Errorf("%s: got %d, want %d", name, rec.Code, c.want)
		}
	}
}

func TestCrossSiteRequestBlocked(t *testing.T) {
	_, h := newTestServer(t)
	rec := do(h, "POST", "/api/v1/notes", validCreate([]byte("x")),
		map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site POST: %d, want 403", rec.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	_, h := newTestServer(t)
	for _, path := range []string{"/", "/n/" + strings.Repeat("A", 22), "/static/note.js", "/nope"} {
		rec := do(h, "GET", path, "", nil)
		for _, k := range []string{
			"Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options",
			"Referrer-Policy", "Cross-Origin-Opener-Policy", "X-Frame-Options", "Permissions-Policy",
		} {
			if rec.Header().Get(k) == "" {
				t.Errorf("%s: missing %s", path, k)
			}
		}
		if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "require-trusted-types-for 'script'") {
			t.Errorf("%s: CSP lacks Trusted Types", path)
		}
	}
	rec := do(h, "GET", "/", "", nil)
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("HTML must be no-store")
	}
	if !strings.Contains(rec.Body.String(), `integrity="sha384-`) {
		t.Error("page must use SRI")
	}

	// Every script and stylesheet on both pages carries an SRI hash, and no
	// inline styles or scripts sneak in (CSP would block them in the browser).
	for _, path := range []string{"/", "/n/" + strings.Repeat("A", 22)} {
		body := html.UnescapeString(do(h, "GET", path, "", nil).Body.String())
		for _, asset := range []string{"/static/note.js", "/static/theme.js", "/static/note.css"} {
			re := regexp.MustCompile(regexp.QuoteMeta(asset) + `" integrity="sha384-[A-Za-z0-9+/=]{64}"`)
			if !re.MatchString(body) {
				t.Errorf("%s: %s without SRI", path, asset)
			}
		}
		if regexp.MustCompile(`\sstyle=|<script>|\son[a-z]+=`).MatchString(body) {
			t.Errorf("%s: inline style or script found", path)
		}
	}
}

func TestPathTraversalNotServed(t *testing.T) {
	_, h := newTestServer(t)
	for _, p := range []string{"/api/v1/notes/../../etc/passwd/take", "/n/../../main.go", "/static/..%2fembed.go"} {
		if rec := do(h, "POST", p, `{"token":"x"}`, nil); rec.Code == http.StatusOK {
			t.Errorf("POST %s returned 200", p)
		}
		if rec := do(h, "GET", p, "", nil); rec.Code == http.StatusOK && !strings.HasPrefix(p, "/n/") {
			t.Errorf("GET %s returned 200", p)
		}
	}
}

func TestStaticAllowList(t *testing.T) {
	_, h := newTestServer(t)
	for _, p := range []string{"/static/", "/static/../embed.go", "/static/templates", "/static/note.js.map"} {
		if rec := do(h, "GET", p, "", nil); rec.Code == http.StatusOK {
			t.Errorf("%s must not be served", p)
		}
	}
	for _, p := range []string{"/static/note.js", "/static/theme.js"} {
		if rec := do(h, "GET", p, "", nil); rec.Code != 200 ||
			!strings.HasPrefix(rec.Header().Get("Content-Type"), "text/javascript") {
			t.Errorf("%s: %d %s", p, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
	if rec := do(h, "GET", "/static/partials.html", "", nil); rec.Code == http.StatusOK {
		t.Error("templates must not be served as static files")
	}

	// Fonts: only the allow-listed woff2 files, revalidated by ETag.
	font := "/static/fonts/IBMPlexSans-Regular-Cyrillic.woff2"
	rec := do(h, "GET", font, "", nil)
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "font/woff2" ||
		!bytes.HasPrefix(rec.Body.Bytes(), []byte("wOF2")) {
		t.Fatalf("font: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("font: no ETag")
	}
	if rec := do(h, "GET", font, "", map[string]string{"If-None-Match": etag}); rec.Code != http.StatusNotModified {
		t.Errorf("font revalidation: %d, want 304", rec.Code)
	}
	for _, p := range []string{
		"/static/fonts/LICENSE-IBM-Plex.txt", "/static/fonts/", "/static/fonts/note.js",
		"/static/fonts/..%2fnote.js", "/static/fonts/IBMPlexSans-Bold-Latin1.woff2",
	} {
		if rec := do(h, "GET", p, "", nil); rec.Code == http.StatusOK {
			t.Errorf("%s must not be served", p)
		}
	}
	if !strings.Contains(do(h, "GET", "/", "", nil).Header().Get("Content-Security-Policy"), "font-src 'self'") {
		t.Error("CSP must allow same-origin fonts only")
	}
}

func TestRateLimit(t *testing.T) {
	h := newRealLimitsServer(t).Handler()
	limited := false
	for i := 0; i < 15; i++ {
		if rec := do(h, "POST", "/api/v1/notes", validCreate([]byte("x")), nil); rec.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("create endpoint is not rate limited")
	}
}

func TestClientIPIgnoresForwardedHeaderByDefault(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.5:1234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := s.clientIP(req); got != "203.0.113.5" {
		t.Fatalf("spoofable XFF trusted: %s", got)
	}
	s.cfg.TrustProxy = true
	req.Header.Set("X-Forwarded-For", "2001:db8:1:2:3:4:5:6")
	if got := s.clientIP(req); got != "2001:db8:1:2::/64" {
		t.Fatalf("IPv6 must be grouped by /64: %s", got)
	}
}

func FuzzCreate(f *testing.F) {
	f.Add(validCreate([]byte("x")))
	f.Add(`{"ciphertext":"","token_hash":"","ttl":0}`)
	f.Add(`{}`)
	f.Add(`[`)
	s, err := New(Config{}, store.New(1_000_000, 1<<30))
	if err != nil {
		f.Fatal(err)
	}
	s.createLimit = newLimiter(1<<30, 1<<30, 1<<20)
	h := s.Handler()
	f.Fuzz(func(t *testing.T, body string) {
		rec := do(h, "POST", "/api/v1/notes", body, map[string]string{"Content-Type": "application/json"})
		switch rec.Code {
		case 201, 400, 413:
		default:
			t.Fatalf("unexpected status %d for %q", rec.Code, body)
		}
	})
}

func FuzzTake(f *testing.F) {
	f.Add(strings.Repeat("A", 22), `{"token":"`+b64.EncodeToString(make([]byte, 32))+`"}`)
	f.Add("x", `{}`)
	s, err := New(Config{}, store.New(10, 1<<20))
	if err != nil {
		f.Fatal(err)
	}
	s.takeLimit = newLimiter(1<<30, 1<<30, 1<<20)
	h := s.Handler()
	f.Fuzz(func(t *testing.T, id, body string) {
		if id == "" || id == "." || id == ".." {
			return
		}
		rec := do(h, "POST", "/api/v1/notes/"+url.PathEscape(id)+"/take", body,
			map[string]string{"Content-Type": "application/json"})
		switch rec.Code {
		case 400, 404, 413:
		default:
			t.Fatalf("unexpected status %d", rec.Code)
		}
	})
}
