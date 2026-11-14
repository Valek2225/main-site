package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"

	"rima.su/vault/internal/access"
	"rima.su/vault/internal/account"
	"rima.su/vault/internal/blobs"
)

const (
	maxBody    = 32 << 10
	cookieName = "__Host-session"

	actRead   = access.Read
	actWrite  = access.Write
	actShare  = access.Share
	actDelete = access.Delete
)

var b64 = base64.RawURLEncoding.Strict()

// --- wire types: every field is validated after decoding ---

type credsJSON struct {
	Salt       string `json:"salt"`
	Iterations int    `json:"iterations"`
	AuthKey    string `json:"auth_key"`
	MetaKey    string `json:"meta_key"`
	Keyset     string `json:"keyset"`
}

type recoveryJSON struct {
	AuthKey string `json:"auth_key"`
	MetaKey string `json:"meta_key"`
	Keyset  string `json:"keyset,omitempty"`
}

type preloginRequest struct {
	Login string `json:"login"`
}

type preloginResponse struct {
	Salt       string `json:"salt"`
	Iterations int    `json:"iterations"`
}

type loginRequest struct {
	Login   string `json:"login"`
	AuthKey string `json:"auth_key"`
	MetaKey string `json:"meta_key"`
}

type registerRequest struct {
	Login       string       `json:"login"`
	Invite      string       `json:"invite"`
	Creds       credsJSON    `json:"credentials"`
	Recovery    recoveryJSON `json:"recovery"`
	IdentityPub string       `json:"identity_pub"`
	ExchangePub string       `json:"exchange_pub"`
	IdentitySig string       `json:"identity_sig"`
}

type recoveryKeysetRequest struct {
	Login        string `json:"login"`
	RecoveryAuth string `json:"recovery_auth"`
}

type recoveryResetRequest struct {
	Login       string       `json:"login"`
	Recovery    recoveryJSON `json:"recovery"`
	Creds       credsJSON    `json:"credentials"`
	NewRecovery recoveryJSON `json:"new_recovery"`
}

type passwordRequest struct {
	CurrentAuthKey string    `json:"current_auth_key"`
	Creds          credsJSON `json:"credentials"`
}

type deleteRequest struct {
	AuthKey string `json:"auth_key"`
}

type accountResponse struct {
	Login       string `json:"login"`
	UserID      string `json:"user_id"`
	IdentityPub string `json:"identity_pub"`
	ExchangePub string `json:"exchange_pub"`
	Keyset      string `json:"keyset"`
	Admin       bool   `json:"admin"`
	CreatedAt   int64  `json:"created_at"`
}

type keysetResponse struct {
	Keyset string `json:"keyset"`
}

type inviteResponse struct {
	Code      string `json:"code"`
	ExpiresAt int64  `json:"expires_at"`
}

type objectsResponse struct {
	Objects []string `json:"objects"`
}

type apiError struct {
	Error string `json:"error"`
}

// dec decodes base64url; any malformed field makes the whole request invalid.
type dec struct{ bad bool }

func (d *dec) b(s string) []byte {
	v, err := b64.DecodeString(s)
	if err != nil {
		d.bad = true
	}
	return v
}

func (d *dec) creds(c credsJSON) account.Credentials {
	return account.Credentials{Salt: d.b(c.Salt), Iterations: c.Iterations,
		AuthKey: d.b(c.AuthKey), MetaKey: d.b(c.MetaKey), Keyset: d.b(c.Keyset)}
}

func (d *dec) recovery(r recoveryJSON) account.Recovery {
	rec := account.Recovery{AuthKey: d.b(r.AuthKey), MetaKey: d.b(r.MetaKey)}
	if r.Keyset != "" {
		rec.Keyset = d.b(r.Keyset)
	}
	return rec
}

func accountJSON(i *account.Info) accountResponse {
	return accountResponse{Login: i.Login, UserID: b64.EncodeToString(i.UserID),
		IdentityPub: b64.EncodeToString(i.IdentityPub), ExchangePub: b64.EncodeToString(i.ExchangePub),
		Keyset: b64.EncodeToString(i.Keyset), Admin: i.Admin, CreatedAt: i.CreatedAt.Unix()}
}

// --- session cookie ---

func setSession(w http.ResponseWriter, sess *account.Session) {
	// No Expires: the cookie dies with the browser session; the server enforces
	// idle and absolute lifetimes on its own.
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: b64.EncodeToString(sess.Token), Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

func clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

func sessionToken(r *http.Request) []byte {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}
	t, err := b64.DecodeString(c.Value)
	if err != nil {
		return nil
	}
	return t
}

type authedHandler func(http.ResponseWriter, *http.Request, *account.Principal)

func (s *Server) authed(next authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := s.acc.Authenticate(sessionToken(r))
		if err != nil {
			s.fail(w, err)
			return
		}
		next(w, r, p)
	}
}

// fail maps service errors to generic responses; details stay in the log.
func (s *Server) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, account.ErrBadInput):
		writeError(w, http.StatusBadRequest, "bad request")
	case errors.Is(err, account.ErrAuth):
		writeError(w, http.StatusUnauthorized, "invalid credentials")
	case errors.Is(err, account.ErrNoSession):
		clearSession(w)
		writeError(w, http.StatusUnauthorized, "not signed in")
	case errors.Is(err, account.ErrInvite):
		writeError(w, http.StatusForbidden, "invalid invite")
	case errors.Is(err, account.ErrLoginTaken):
		writeError(w, http.StatusConflict, "login unavailable")
	case errors.Is(err, account.ErrForbidden):
		writeError(w, http.StatusForbidden, "forbidden")
	case errors.Is(err, account.ErrThrottled):
		w.Header().Set("Retry-After", "180")
		writeError(w, http.StatusTooManyRequests, "too many attempts")
	case errors.Is(err, account.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	default:
		slog.Error("internal error", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

// --- handlers ---

func (s *Server) handlePrelogin(w http.ResponseWriter, r *http.Request) {
	var req preloginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	salt, iter, err := s.acc.Prelogin(req.Login)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, preloginResponse{Salt: b64.EncodeToString(salt), Iterations: iter})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	var d dec
	ak, mk := d.b(req.AuthKey), d.b(req.MetaKey)
	if d.bad {
		s.fail(w, account.ErrBadInput)
		return
	}
	sess, info, err := s.acc.Login(req.Login, ak, mk)
	clear(ak)
	clear(mk)
	if err != nil {
		s.fail(w, err)
		return
	}
	setSession(w, sess)
	writeJSON(w, http.StatusOK, accountJSON(info))
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	var d dec
	in := account.RegisterInput{
		Login: req.Login, Invite: d.b(req.Invite), Creds: d.creds(req.Creds),
		Recovery: d.recovery(req.Recovery), IdentityPub: d.b(req.IdentityPub),
		ExchangePub: d.b(req.ExchangePub), IdentitySig: d.b(req.IdentitySig),
	}
	if d.bad || in.Recovery.Keyset == nil {
		s.fail(w, account.ErrBadInput)
		return
	}
	sess, info, err := s.acc.Register(in)
	if err != nil {
		s.fail(w, err)
		return
	}
	setSession(w, sess)
	writeJSON(w, http.StatusCreated, accountJSON(info))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if t := sessionToken(r); t != nil {
		if err := s.acc.Logout(t); err != nil {
			s.fail(w, err)
			return
		}
	}
	clearSession(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRecoveryKeyset(w http.ResponseWriter, r *http.Request) {
	var req recoveryKeysetRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	var d dec
	ra := d.b(req.RecoveryAuth)
	if d.bad {
		s.fail(w, account.ErrBadInput)
		return
	}
	ks, err := s.acc.RecoveryKeyset(req.Login, ra)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, keysetResponse{Keyset: b64.EncodeToString(ks)})
}

func (s *Server) handleRecoveryReset(w http.ResponseWriter, r *http.Request) {
	var req recoveryResetRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	var d dec
	old, c, next := d.recovery(req.Recovery), d.creds(req.Creds), d.recovery(req.NewRecovery)
	if d.bad {
		s.fail(w, account.ErrBadInput)
		return
	}
	sess, err := s.acc.Recover(req.Login, old, c, next)
	if err != nil {
		s.fail(w, err)
		return
	}
	setSession(w, sess)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request, p *account.Principal) {
	info, err := s.acc.Info(p)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, accountJSON(info))
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request, p *account.Principal) {
	var req passwordRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	var d dec
	cur, c := d.b(req.CurrentAuthKey), d.creds(req.Creds)
	if d.bad {
		s.fail(w, account.ErrBadInput)
		return
	}
	sess, err := s.acc.ChangePassword(p, cur, c)
	if err != nil {
		s.fail(w, err)
		return
	}
	setSession(w, sess)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request, p *account.Principal) {
	var req deleteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	var d dec
	ak := d.b(req.AuthKey)
	if d.bad {
		s.fail(w, account.ErrBadInput)
		return
	}
	if err := s.acc.DeleteAccount(p, ak); err != nil {
		s.fail(w, err)
		return
	}
	clearSession(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleInvite(w http.ResponseWriter, r *http.Request, p *account.Principal) {
	code, exp, err := s.acc.CreateInvite(p)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, inviteResponse{Code: b64.EncodeToString(code), ExpiresAt: exp.Unix()})
}

func (s *Server) handleListObjects(w http.ResponseWriter, r *http.Request, p *account.Principal) {
	ids, err := s.acc.Objects(p)
	if err != nil {
		s.fail(w, err)
		return
	}
	out := objectsResponse{Objects: make([]string, 0, len(ids))}
	for _, id := range ids {
		out.Objects = append(out.Objects, b64.EncodeToString(id))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateObject(w http.ResponseWriter, r *http.Request, p *account.Principal) {
	writeError(w, http.StatusNotImplemented, "not implemented")
}

// objectStub authenticates, validates the ID and checks access, then refuses:
// object storage arrives in the next stage, but the access path is final.
func (s *Server) objectStub(act access.Action) authedHandler {
	return func(w http.ResponseWriter, r *http.Request, p *account.Principal) {
		raw := r.PathValue("id")
		if !blobs.ValidID(raw) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		id, err := b64.DecodeString(raw)
		if err != nil {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		if err := s.acc.Authorize(p, id, act); err != nil {
			s.fail(w, err)
			return
		}
		writeError(w, http.StatusNotImplemented, "not implemented")
	}
}

// decodeJSON enforces content type, body size, known fields and a single value.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "content type must be application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "request too large")
		} else {
			writeError(w, http.StatusBadRequest, "bad json")
		}
		return false
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "bad json")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, apiError{Error: msg})
}
