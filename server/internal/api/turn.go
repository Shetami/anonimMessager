package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"time"
)

// TURNConfig enables GET /v1/turn: short-lived credentials for a TURN server
// (coturn with use-auth-secret) that shares Secret with the relay. Calls are
// always relayed through it, so peers never learn each other's IP address.
type TURNConfig struct {
	Secret []byte
	URLs   []string
	TTL    time.Duration
}

type turnCredentials struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	URLs     []string `json:"urls"`
	TTL      int64    `json:"ttl"`
}

// turn issues credentials in coturn's "TURN REST API" format:
// username = "<expiry unix>:<random>", password = base64(HMAC-SHA1(secret, username)).
// Unauthenticated on purpose: tying credentials to a mailbox would tell the
// relay which account is about to make a call. Clients fetch them ahead of
// time and cache them, so the request's timing doesn't reveal calls either.
func (s *Server) turn(w http.ResponseWriter, _ *http.Request) {
	if s.TURN == nil || len(s.TURN.Secret) == 0 || len(s.TURN.URLs) == 0 {
		httpError(w, http.StatusNotFound)
		return
	}
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		httpError(w, http.StatusInternalServerError)
		return
	}
	username := strconv.FormatInt(s.now().Add(s.TURN.TTL).Unix(), 10) + ":" + hex.EncodeToString(nonce)
	mac := hmac.New(sha1.New, s.TURN.Secret)
	mac.Write([]byte(username))
	writeJSON(w, http.StatusOK, turnCredentials{
		Username: username,
		Password: base64.StdEncoding.EncodeToString(mac.Sum(nil)),
		URLs:     s.TURN.URLs,
		TTL:      int64(s.TURN.TTL / time.Second),
	})
}
