package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"time"

	"rima.su/note/internal/store"
)

// Protocol constants. They must match web/static/note.js.
const (
	nonceBytes = 12
	tagBytes   = 16
	tokenBytes = 32

	maxCreateBody = 96 << 10 // ~87.5 KiB of base64 ciphertext + JSON overhead
	maxTakeBody   = 1 << 10
)

// Allowed padded plaintext sizes. The client pads every message up to one of
// these, so the ciphertext length reveals only a coarse size class.
var paddedSizes = map[int]bool{
	512: true, 2048: true, 8192: true, 32768: true, 65536: true,
}

var allowedTTL = map[int]time.Duration{
	3600:   time.Hour,
	86400:  24 * time.Hour,
	604800: 7 * 24 * time.Hour,
}

type createRequest struct {
	Ciphertext string `json:"ciphertext"`
	TokenHash  string `json:"token_hash"`
	TTL        int    `json:"ttl"`
}

type createResponse struct {
	ID string `json:"id"`
}

type takeRequest struct {
	Token string `json:"token"`
}

type takeResponse struct {
	Ciphertext string `json:"ciphertext"`
}

type apiError struct {
	Error string `json:"error"`
}

var b64 = base64.RawURLEncoding

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if !decodeJSON(w, r, maxCreateBody, &req) {
		return
	}

	ct, err := b64.Strict().DecodeString(req.Ciphertext)
	if err != nil || !paddedSizes[len(ct)-nonceBytes-tagBytes] {
		writeError(w, http.StatusBadRequest, "bad ciphertext")
		return
	}
	th, err := b64.Strict().DecodeString(req.TokenHash)
	if err != nil || len(th) != store.TokenHashBytes {
		writeError(w, http.StatusBadRequest, "bad token_hash")
		return
	}
	ttl, ok := allowedTTL[req.TTL]
	if !ok {
		writeError(w, http.StatusBadRequest, "bad ttl")
		return
	}

	var hash [store.TokenHashBytes]byte
	copy(hash[:], th)

	id, err := s.store.Put(ct, hash, ttl)
	if errors.Is(err, store.ErrFull) {
		writeError(w, http.StatusServiceUnavailable, "service is busy, try later")
		return
	}
	if err != nil {
		slog.Error("store put failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusCreated, createResponse{ID: id})
}

func (s *Server) handleTake(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID(id) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}

	var req takeRequest
	if !decodeJSON(w, r, maxTakeBody, &req) {
		return
	}
	token, err := b64.Strict().DecodeString(req.Token)
	if err != nil || len(token) != tokenBytes {
		writeError(w, http.StatusBadRequest, "bad token")
		return
	}

	ct, err := s.store.Take(id, token)
	clear(token)
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}

	writeJSON(w, http.StatusOK, takeResponse{Ciphertext: b64.EncodeToString(ct)})
	clear(ct)
}

// validID accepts exactly 22 base64url characters (128-bit IDs).
func validID(id string) bool {
	if len(id) != 22 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// decodeJSON enforces content type, body size, known fields and a single value.
func decodeJSON(w http.ResponseWriter, r *http.Request, limit int64, dst any) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "content type must be application/json")
		return false
	}

	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "request too large")
		} else {
			writeError(w, http.StatusBadRequest, "bad json")
		}
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
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
