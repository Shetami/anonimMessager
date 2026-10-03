// Package api exposes the relay's HTTP interface.
//
// Endpoints:
//
//	POST   /v1/accounts               register (signed with the new auth key)
//	DELETE /v1/accounts               delete own account and all queued data (auth)
//	GET    /v1/accounts/{id}/bundle   fetch a prekey bundle (unauthenticated)
//	PUT    /v1/keys                   rotate / replenish prekeys (auth)
//	GET    /v1/keys/count             remaining one-time prekeys (auth)
//	PUT    /v1/messages/{id}          deposit a sealed envelope (unauthenticated, no sender)
//	GET    /v1/messages               fetch own envelopes (auth)
//	POST   /v1/messages/ack           delete fetched envelopes (auth)
//	PUT    /v1/attachments/{id}       upload an encrypted attachment (unauthenticated)
//	GET    /v1/attachments/{id}       download it (the random ID is the capability)
//	DELETE /v1/attachments/{id}       delete it once downloaded
//
// Deliberately absent: request logging, IP storage, sender identification.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/shetami/anonimmessager/server/internal/blobs"
	"github.com/shetami/anonimmessager/server/internal/store"
)

const (
	maxEnvelope   = 256 << 10
	maxJSONBody   = 512 << 10
	maxPreKeys    = 200
	fetchPageSize = 100
	// Attachments are far larger than envelopes: give their transfers more
	// time than the server-wide timeouts allow.
	attachmentTimeout = 15 * time.Minute
)

type Server struct {
	store   *store.Store
	blobs   *blobs.Store // nil = attachments disabled
	replays *replayCache
	now     func() time.Time
	// DebugAuth logs why authentication failed (never IPs or bodies). Clients
	// always get the same 401 either way.
	DebugAuth bool
}

func (s *Server) authFail(w http.ResponseWriter, r *http.Request, reason string) {
	if s.DebugAuth {
		log.Printf("auth rejected: %s %s: %s", r.Method, r.URL.Path, reason)
	}
	httpError(w, http.StatusUnauthorized)
}

func New(s *store.Store, b *blobs.Store) *Server {
	return &Server{store: s, blobs: b, replays: newReplayCache(), now: time.Now}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/accounts", s.register)
	mux.HandleFunc("DELETE /v1/accounts", s.authed(s.deleteAccount))
	mux.HandleFunc("GET /v1/accounts/{id}/bundle", s.bundle)
	mux.HandleFunc("PUT /v1/keys", s.authed(s.updateKeys))
	mux.HandleFunc("GET /v1/keys/count", s.authed(s.keyCount))
	mux.HandleFunc("PUT /v1/messages/{id}", s.send)
	mux.HandleFunc("GET /v1/messages", s.authed(s.fetch))
	mux.HandleFunc("POST /v1/messages/ack", s.authed(s.ack))
	mux.HandleFunc("PUT /v1/attachments/{id}", s.putAttachment)
	mux.HandleFunc("GET /v1/attachments/{id}", s.getAttachment)
	mux.HandleFunc("DELETE /v1/attachments/{id}", s.deleteAttachment)
	return securityHeaders(mux)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		h.ServeHTTP(w, r)
	})
}

type authedHandler func(w http.ResponseWriter, r *http.Request, accountID string, body []byte)

// authed reads the body, verifies the request signature against the
// account's registered auth key and rejects replays.
func (s *Server) authed(next authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxJSONBody))
		if err != nil {
			httpError(w, http.StatusRequestEntityTooLarge)
			return
		}
		a, err := parseAuth(r)
		if err != nil {
			s.authFail(w, r, err.Error())
			return
		}
		acct, err := s.store.Account(a.id)
		if err != nil {
			s.authFail(w, r, "unknown account")
			return
		}
		now := s.now()
		if err := verify(acct.AuthKey, a, r.Method, r.URL.Path, body, now); err != nil {
			s.authFail(w, r, err.Error())
			return
		}
		if !s.replays.checkAndAdd(a.sig, now) {
			s.authFail(w, r, "replayed request")
			return
		}
		next(w, r, a.id, body)
	}
}

type registerRequest struct {
	IdentityKey     []byte            `json:"identityKey"`
	AuthKey         []byte            `json:"authKey"`
	RegistrationID  uint32            `json:"registrationId"`
	SealingKey      store.SignedKey   `json:"sealingKey"`
	SignedPreKey    store.SignedKey   `json:"signedPreKey"`
	KyberLastResort store.SignedKey   `json:"kyberLastResort"`
	PreKeys         []store.SignedKey `json:"preKeys"`
	KyberPreKeys    []store.SignedKey `json:"kyberPreKeys"`
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxJSONBody))
	if err != nil {
		httpError(w, http.StatusRequestEntityTooLarge)
		return
	}
	var req registerRequest
	if err := json.Unmarshal(body, &req); err != nil {
		httpError(w, http.StatusBadRequest)
		return
	}
	// Serialized libsignal Curve25519 public key: 0x05 || 32 bytes.
	if len(req.IdentityKey) != 33 || req.IdentityKey[0] != 0x05 ||
		len(req.SealingKey.PublicKey) == 0 || len(req.SignedPreKey.PublicKey) == 0 ||
		len(req.KyberLastResort.PublicKey) == 0 ||
		len(req.PreKeys) > maxPreKeys || len(req.KyberPreKeys) > maxPreKeys {
		httpError(w, http.StatusBadRequest)
		return
	}
	id := AccountID(req.IdentityKey)
	// Proof of possession of the auth key; the signed account ID must match
	// the one derived from the identity key.
	a, err := parseAuth(r)
	if err != nil {
		s.authFail(w, r, err.Error())
		return
	}
	if a.id != id {
		s.authFail(w, r, fmt.Sprintf("signed id %q != id derived from identity key %q", a.id, id))
		return
	}
	now := s.now()
	if err := verify(req.AuthKey, a, r.Method, r.URL.Path, body, now); err != nil {
		s.authFail(w, r, err.Error())
		return
	}
	if !s.replays.checkAndAdd(a.sig, now) {
		s.authFail(w, r, "replayed request")
		return
	}
	acct := store.Account{
		ID:              id,
		IdentityKey:     req.IdentityKey,
		AuthKey:         req.AuthKey,
		RegistrationID:  req.RegistrationID,
		SealingKey:      req.SealingKey,
		SignedPreKey:    req.SignedPreKey,
		KyberLastResort: req.KyberLastResort,
	}
	if err := s.store.CreateAccount(acct, req.PreKeys, req.KyberPreKeys); err != nil {
		if errors.Is(err, store.ErrExists) {
			httpError(w, http.StatusConflict)
			return
		}
		httpError(w, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

func (s *Server) deleteAccount(w http.ResponseWriter, _ *http.Request, id string, _ []byte) {
	if err := s.store.DeleteAccount(id); err != nil {
		httpError(w, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) bundle(w http.ResponseWriter, r *http.Request) {
	b, err := s.store.TakeBundle(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		httpError(w, http.StatusNotFound)
		return
	}
	if err != nil {
		httpError(w, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

type keysRequest struct {
	SignedPreKey    *store.SignedKey  `json:"signedPreKey,omitempty"`
	KyberLastResort *store.SignedKey  `json:"kyberLastResort,omitempty"`
	PreKeys         []store.SignedKey `json:"preKeys"`
	KyberPreKeys    []store.SignedKey `json:"kyberPreKeys"`
}

func (s *Server) updateKeys(w http.ResponseWriter, _ *http.Request, id string, body []byte) {
	var req keysRequest
	if err := json.Unmarshal(body, &req); err != nil || len(req.PreKeys) > maxPreKeys || len(req.KyberPreKeys) > maxPreKeys {
		httpError(w, http.StatusBadRequest)
		return
	}
	if err := s.store.UpdateKeys(id, req.SignedPreKey, req.KyberLastResort, req.PreKeys, req.KyberPreKeys); err != nil {
		httpError(w, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) keyCount(w http.ResponseWriter, _ *http.Request, id string, _ []byte) {
	pk, ky, err := s.store.KeyCounts(id)
	if err != nil {
		httpError(w, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"preKeys": pk, "kyberPreKeys": ky})
}

func (s *Server) send(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEnvelope))
	if err != nil {
		httpError(w, http.StatusRequestEntityTooLarge)
		return
	}
	if len(data) == 0 {
		httpError(w, http.StatusBadRequest)
		return
	}
	switch err := s.store.Enqueue(r.PathValue("id"), data); {
	case errors.Is(err, store.ErrNotFound):
		httpError(w, http.StatusNotFound)
	case errors.Is(err, store.ErrQueueFull):
		httpError(w, http.StatusTooManyRequests)
	case err != nil:
		httpError(w, http.StatusInternalServerError)
	default:
		w.WriteHeader(http.StatusAccepted)
	}
}

func (s *Server) fetch(w http.ResponseWriter, _ *http.Request, id string, _ []byte) {
	msgs, err := s.store.Fetch(id, fetchPageSize)
	if err != nil {
		httpError(w, http.StatusInternalServerError)
		return
	}
	if msgs == nil {
		msgs = []store.Envelope{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": msgs})
}

func (s *Server) ack(w http.ResponseWriter, _ *http.Request, id string, body []byte) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.Unmarshal(body, &req); err != nil || len(req.IDs) > fetchPageSize {
		httpError(w, http.StatusBadRequest)
		return
	}
	if err := s.store.Ack(id, req.IDs); err != nil {
		httpError(w, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) putAttachment(w http.ResponseWriter, r *http.Request) {
	if s.blobs == nil {
		httpError(w, http.StatusNotFound)
		return
	}
	_ = http.NewResponseController(w).SetReadDeadline(s.now().Add(attachmentTimeout))
	body := http.MaxBytesReader(w, r.Body, s.blobs.MaxSize())
	var tooLarge *http.MaxBytesError
	switch err := s.blobs.Put(r.PathValue("id"), body); {
	case err == nil:
		w.WriteHeader(http.StatusCreated)
	case errors.As(err, &tooLarge), errors.Is(err, blobs.ErrTooLarge):
		httpError(w, http.StatusRequestEntityTooLarge)
	case errors.Is(err, blobs.ErrBadID), errors.Is(err, blobs.ErrEmpty):
		httpError(w, http.StatusBadRequest)
	case errors.Is(err, blobs.ErrExists):
		httpError(w, http.StatusConflict)
	case errors.Is(err, blobs.ErrFull):
		httpError(w, http.StatusInsufficientStorage)
	default:
		httpError(w, http.StatusInternalServerError)
	}
}

func (s *Server) getAttachment(w http.ResponseWriter, r *http.Request) {
	if s.blobs == nil {
		httpError(w, http.StatusNotFound)
		return
	}
	f, err := s.blobs.Open(r.PathValue("id"))
	if err != nil {
		httpError(w, http.StatusNotFound)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		httpError(w, http.StatusInternalServerError)
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(s.now().Add(attachmentTimeout))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}

func (s *Server) deleteAttachment(w http.ResponseWriter, r *http.Request) {
	if s.blobs == nil {
		httpError(w, http.StatusNotFound)
		return
	}
	switch err := s.blobs.Delete(r.PathValue("id")); {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, blobs.ErrNotFound), errors.Is(err, blobs.ErrBadID):
		httpError(w, http.StatusNotFound)
	default:
		httpError(w, http.StatusInternalServerError)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, status int) {
	http.Error(w, http.StatusText(status), status)
}
