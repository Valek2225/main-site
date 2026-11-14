package server

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"rima.su/vault/internal/account"
	"rima.su/vault/internal/blobs"
	"rima.su/vault/internal/keys"
	"rima.su/vault/internal/store"
	"rima.su/vault/web"
)

var bootstrap = bytes.Repeat([]byte{9}, 32)

func newTest(t testing.TB) http.Handler {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	bs, err := blobs.Open(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bs.Close() })
	srv, err := New(Config{}, account.New(st, keys.ForTest(), account.BootstrapHash(bootstrap)), bs)
	if err != nil {
		t.Fatal(err)
	}
	return srv.Handler()
}

func rnd(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func e(b []byte) string { return b64.EncodeToString(b) }

type client struct {
	t      *testing.T
	h      http.Handler
	cookie *http.Cookie
}

func (c *client) do(method, path string, body any, mod ...func(*http.Request)) *httptest.ResponseRecorder {
	c.t.Helper()
	var rdr *bytes.Reader
	switch b := body.(type) {
	case nil:
		rdr = bytes.NewReader(nil)
	case string:
		rdr = bytes.NewReader([]byte(b))
	default:
		data, _ := json.Marshal(b)
		rdr = bytes.NewReader(data)
	}
	r := httptest.NewRequest(method, path, rdr)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if c.cookie != nil {
		r.AddCookie(c.cookie)
	}
	for _, m := range mod {
		m(r)
	}
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, r)
	for _, ck := range w.Result().Cookies() {
		if ck.Name == cookieName {
			if ck.MaxAge < 0 {
				c.cookie = nil
			} else {
				c.cookie = ck
			}
		}
	}
	return w
}

type creds struct {
	auth, meta []byte
}

func registerBody(login string, invite []byte) (map[string]any, creds) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	x, _ := ecdh.X25519().GenerateKey(rand.Reader)
	xp := x.PublicKey().Bytes()
	c := creds{auth: rnd(32), meta: rnd(32)}
	return map[string]any{
		"login":  login,
		"invite": e(invite),
		"credentials": map[string]any{
			"salt": e(rnd(32)), "iterations": 600000,
			"auth_key": e(c.auth), "meta_key": e(c.meta), "keyset": e(rnd(300)),
		},
		"recovery":     map[string]any{"auth_key": e(rnd(32)), "meta_key": e(rnd(32)), "keyset": e(rnd(300))},
		"identity_pub": e(pub),
		"exchange_pub": e(xp),
		"identity_sig": e(ed25519.Sign(priv, account.RegisterMessage(pub, xp))),
	}, c
}

func TestHeadersOnEveryResponse(t *testing.T) {
	c := &client{t: t, h: newTest(t)}
	for _, path := range []string{"/", "/static/app.js", "/nope", "/api/v1/account"} {
		w := c.do("GET", path, nil)
		h := w.Header()
		for _, k := range []string{"Content-Security-Policy", "Strict-Transport-Security",
			"X-Content-Type-Options", "Referrer-Policy", "Cross-Origin-Opener-Policy",
			"Cross-Origin-Embedder-Policy", "Cross-Origin-Resource-Policy", "Permissions-Policy"} {
			if h.Get(k) == "" {
				t.Errorf("%s: missing %s", path, k)
			}
		}
		if !strings.Contains(h.Get("Content-Security-Policy"), "require-trusted-types-for 'script'") {
			t.Errorf("%s: CSP without Trusted Types", path)
		}
	}
}

func TestPageHasSRI(t *testing.T) {
	c := &client{t: t, h: newTest(t)}
	body := c.do("GET", "/", nil).Body.String()
	for _, want := range []string{`src="/static/app.js" integrity="sha384-`, `href="/static/app.css" integrity="sha384-`,
		`src="/static/theme.js" integrity="sha384-`,
		`data-words-integrity="sha384-`, `data-blocklist-integrity="sha384-`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}
	// CSP (style-src/script-src 'self') would block inline styles, scripts
	// and event handlers in the browser: none may appear in the page.
	if m := regexp.MustCompile(`\sstyle=|<script>|\son[a-z]+=`).FindString(body); m != "" {
		t.Errorf("page has inline style or script: %q", m)
	}
}

func TestFullFlow(t *testing.T) {
	c := &client{t: t, h: newTest(t)}
	body, cr := registerBody("alice", bootstrap)
	w := c.do("POST", "/api/v1/auth/register", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", w.Code, w.Body)
	}
	ck := c.cookie
	if ck == nil || !ck.Secure || !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/" || ck.Domain != "" {
		t.Fatalf("bad session cookie: %+v", ck)
	}
	if strings.Contains(w.Body.String(), e(cr.auth)) || strings.Contains(w.Body.String(), e(cr.meta)) {
		t.Fatal("response echoes secrets")
	}

	w = c.do("GET", "/api/v1/account", nil)
	var acc accountResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &acc) != nil || acc.Login != "alice" || !acc.Admin {
		t.Fatalf("account: %d %s", w.Code, w.Body)
	}

	w = c.do("POST", "/api/v1/invites", nil)
	var inv inviteResponse
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &inv) != nil {
		t.Fatalf("invite: %d", w.Code)
	}

	w = c.do("GET", "/api/v1/objects", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"objects":[]`) {
		t.Fatalf("objects: %d %s", w.Code, w.Body)
	}
	id := blobs.NewID()
	for _, m := range []string{"GET", "PUT", "DELETE"} {
		if w := c.do(m, "/api/v1/objects/"+id, nil); w.Code != http.StatusNotFound {
			t.Errorf("%s unknown object: %d", m, w.Code)
		}
	}
	if w := c.do("GET", "/api/v1/objects/..%2f..%2fetc", nil); w.Code != http.StatusNotFound {
		t.Errorf("traversal id: %d", w.Code)
	}
	if w := c.do("POST", "/api/v1/objects", "{}"); w.Code != http.StatusNotImplemented {
		t.Errorf("create object: %d", w.Code)
	}

	if w := c.do("POST", "/api/v1/auth/logout", nil); w.Code != http.StatusNoContent || c.cookie != nil {
		t.Fatalf("logout: %d", w.Code)
	}
	c.cookie = ck // replay the old cookie
	if w := c.do("GET", "/api/v1/account", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("old cookie after logout: %d", w.Code)
	}

	c.cookie = nil
	w = c.do("POST", "/api/v1/auth/login", map[string]string{"login": "alice", "auth_key": e(cr.auth), "meta_key": e(cr.meta)})
	if w.Code != 200 || c.cookie == nil {
		t.Fatalf("login: %d", w.Code)
	}

	// The invite works exactly once.
	c2 := &client{t: t, h: c.h}
	b2, _ := registerBody("bob", mustB64(t, inv.Code))
	if w := c2.do("POST", "/api/v1/auth/register", b2); w.Code != http.StatusCreated {
		t.Fatalf("invited register: %d %s", w.Code, w.Body)
	}
	if w := c2.do("POST", "/api/v1/invites", nil); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin invite: %d", w.Code)
	}
	b3, _ := registerBody("carol", mustB64(t, inv.Code))
	if w := (&client{t: t, h: c.h}).do("POST", "/api/v1/auth/register", b3); w.Code != http.StatusForbidden {
		t.Fatalf("reused invite: %d", w.Code)
	}
}

func mustB64(t *testing.T, s string) []byte {
	b, err := b64.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRejectsBadRequests(t *testing.T) {
	c := &client{t: t, h: newTest(t)}
	cases := []struct {
		name   string
		body   any
		mod    func(*http.Request)
		status int
	}{
		{"unknown field", `{"login":"alice","extra":1}`, nil, 400},
		{"two values", `{"login":"alice"}{"login":"bob"}`, nil, 400},
		{"not json", `login=alice`, nil, 400},
		{"wrong content type", `{"login":"alice"}`, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 415},
		{"huge body", `{"login":"` + strings.Repeat("a", maxBody) + `"}`, nil, 413},
		{"bad login", `{"login":"../../etc"}`, nil, 400},
		{"cross-site", `{"login":"alice"}`, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
		{"foreign origin", `{"login":"alice"}`, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, 403},
	}
	for _, tc := range cases {
		mods := []func(*http.Request){}
		if tc.mod != nil {
			mods = append(mods, tc.mod)
		}
		if w := c.do("POST", "/api/v1/auth/prelogin", tc.body, mods...); w.Code != tc.status {
			t.Errorf("%s: got %d, want %d", tc.name, w.Code, tc.status)
		}
	}
}

func TestRegisterRejectsBadBase64AndBadKeys(t *testing.T) {
	c := &client{t: t, h: newTest(t)}
	body, _ := registerBody("alice", bootstrap)
	body["identity_pub"] = "!!!"
	if w := c.do("POST", "/api/v1/auth/register", body); w.Code != 400 {
		t.Fatalf("bad base64: %d", w.Code)
	}
	body, _ = registerBody("alice", bootstrap)
	body["identity_sig"] = e(rnd(64))
	if w := c.do("POST", "/api/v1/auth/register", body); w.Code != 400 {
		t.Fatalf("bad signature: %d", w.Code)
	}
	body, _ = registerBody("alice", bootstrap)
	body["credentials"].(map[string]any)["iterations"] = 1
	if w := c.do("POST", "/api/v1/auth/register", body); w.Code != 400 {
		t.Fatalf("weak iterations: %d", w.Code)
	}
	body, _ = registerBody("alice", rnd(32))
	if w := c.do("POST", "/api/v1/auth/register", body); w.Code != 403 {
		t.Fatalf("random invite: %d", w.Code)
	}
}

func TestNeedsSession(t *testing.T) {
	c := &client{t: t, h: newTest(t)}
	c.cookie = &http.Cookie{Name: cookieName, Value: e(rnd(32))}
	for _, r := range []struct{ m, p string }{
		{"GET", "/api/v1/account"}, {"POST", "/api/v1/invites"}, {"GET", "/api/v1/objects"},
		{"GET", "/api/v1/objects/" + blobs.NewID()}, {"POST", "/api/v1/account/delete"},
	} {
		if w := c.do(r.m, r.p, nil); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without session: %d", r.m, r.p, w.Code)
		}
	}
}

func TestLoginRateLimited(t *testing.T) {
	c := &client{t: t, h: newTest(t)}
	got429 := false
	for i := 0; i < 40; i++ {
		w := c.do("POST", "/api/v1/auth/login", map[string]string{"login": "alice", "auth_key": e(rnd(32)), "meta_key": e(rnd(32))})
		if w.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	if !got429 {
		t.Fatal("no rate limit on login")
	}
}

func TestPreloginSameShapeForUnknownLogin(t *testing.T) {
	c := &client{t: t, h: newTest(t)}
	body, _ := registerBody("alice", bootstrap)
	c.do("POST", "/api/v1/auth/register", body)
	var a, b preloginResponse
	_ = json.Unmarshal(c.do("POST", "/api/v1/auth/prelogin", map[string]string{"login": "alice"}).Body.Bytes(), &a)
	_ = json.Unmarshal(c.do("POST", "/api/v1/auth/prelogin", map[string]string{"login": "ghost"}).Body.Bytes(), &b)
	if len(a.Salt) != len(b.Salt) || a.Iterations != b.Iterations || b.Salt == "" {
		t.Fatalf("prelogin reveals account existence: %+v %+v", a, b)
	}
}

func TestStaticAllowList(t *testing.T) {
	c := &client{t: t, h: newTest(t)}
	for _, p := range []string{"/static/../main.go", "/static/embed.go", "/static/", "/static/app.html",
		"/static/fonts/", "/static/fonts/LICENSE-IBM-Plex.txt", "/static/fonts/app.js",
		"/static/fonts/..%2fapp.js", "/static/fonts/IBMPlexSans-Bold-Latin1.woff2"} {
		if w := c.do("GET", p, nil); w.Code == 200 {
			t.Errorf("%s served", p)
		}
	}

	if w := c.do("GET", "/static/theme.js", nil); w.Code != 200 ||
		!strings.HasPrefix(w.Header().Get("Content-Type"), "text/javascript") {
		t.Errorf("theme.js: %d %q", w.Code, w.Header().Get("Content-Type"))
	}

	font := "/static/fonts/IBMPlexSans-Regular-Cyrillic.woff2"
	w := c.do("GET", font, nil)
	if w.Code != 200 || w.Header().Get("Content-Type") != "font/woff2" || !bytes.HasPrefix(w.Body.Bytes(), []byte("wOF2")) {
		t.Fatalf("font: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	etag := w.Header().Get("ETag")
	if etag == "" {
		t.Fatal("font: no ETag")
	}
	r := httptest.NewRequest("GET", font, nil)
	r.Header.Set("If-None-Match", etag)
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, r)
	if rec.Code != http.StatusNotModified {
		t.Errorf("font revalidation: %d, want 304", rec.Code)
	}
}

func TestWordList(t *testing.T) {
	data, err := fs.ReadFile(web.Static, "static/words.txt")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`^[a-z]{3,12}$`)
	seen := map[string]bool{}
	for _, w := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if !re.MatchString(w) || seen[w] || strings.Contains(w, "rima") || strings.Contains(w, "trebuchet") {
			t.Fatalf("bad word %q", w)
		}
		seen[w] = true
	}
	if len(seen) < 1024 {
		t.Fatalf("only %d words", len(seen))
	}
}

func FuzzRegisterRequest(f *testing.F) {
	body, _ := registerBody("alice", bootstrap)
	seed, _ := json.Marshal(body)
	f.Add(string(seed))
	f.Add(`{"login":"a","credentials":{"iterations":-1}}`)
	h := newTest(f)
	f.Fuzz(func(t *testing.T, s string) {
		r := httptest.NewRequest("POST", "/api/v1/auth/register", strings.NewReader(s))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code == http.StatusInternalServerError {
			t.Fatalf("500 for %q", s)
		}
	})
}
