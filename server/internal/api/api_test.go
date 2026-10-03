package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/shetami/anonimmessager/server/internal/store"
)

type client struct {
	t    *testing.T
	srv  *httptest.Server
	id   string
	priv ed25519.PrivateKey
}

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"), time.Hour, 3)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := httptest.NewServer(New(st).Handler())
	t.Cleanup(srv.Close)
	return srv
}

func (c *client) do(method, path string, body []byte, auth bool) *http.Response {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.srv.URL+path, bytes.NewReader(body))
	if auth {
		ts := time.Now().Unix()
		nonce := hex.EncodeToString(randBytes(16))
		sig := ed25519.Sign(c.priv, SigningPayload(method, path, ts, nonce, body))
		req.Header.Set("Authorization", fmt.Sprintf("Calc %s:%d:%s:%s", c.id, ts, nonce, base64.StdEncoding.EncodeToString(sig)))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	c.t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func register(t *testing.T, srv *httptest.Server, preKeys int) *client {
	t.Helper()
	ik := append([]byte{0x05}, randBytes(32)...)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	req := registerRequest{
		IdentityKey:     ik,
		AuthKey:         pub,
		RegistrationID:  42,
		SealingKey:      store.SignedKey{PublicKey: randBytes(32), Signature: randBytes(64)},
		SignedPreKey:    store.SignedKey{ID: 1, PublicKey: randBytes(33), Signature: randBytes(64)},
		KyberLastResort: store.SignedKey{ID: 1, PublicKey: randBytes(64), Signature: randBytes(64)},
	}
	for i := 0; i < preKeys; i++ {
		req.PreKeys = append(req.PreKeys, store.SignedKey{ID: uint32(i + 1), PublicKey: randBytes(33)})
	}
	body, _ := json.Marshal(req)
	c := &client{t: t, srv: srv, id: AccountID(ik), priv: priv}
	if resp := c.do("POST", "/v1/accounts", body, true); resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d", resp.StatusCode)
	}
	return c
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func TestMessageRoundTrip(t *testing.T) {
	srv := newServer(t)
	alice := register(t, srv, 0)
	bob := register(t, srv, 2)

	// Bundle fetch consumes one-time prekeys, then falls back to none.
	for _, wantPreKey := range []bool{true, true, false} {
		resp := alice.do("GET", "/v1/accounts/"+bob.id+"/bundle", nil, false)
		var b store.Bundle
		json.NewDecoder(resp.Body).Decode(&b)
		if (b.PreKey != nil) != wantPreKey {
			t.Fatalf("preKey present = %v, want %v", b.PreKey != nil, wantPreKey)
		}
	}

	// Sending is unauthenticated and carries no sender.
	envelope := randBytes(1024)
	anon := &client{t: t, srv: srv}
	if resp := anon.do("PUT", "/v1/messages/"+bob.id, envelope, false); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("send: %d", resp.StatusCode)
	}

	resp := bob.do("GET", "/v1/messages", nil, true)
	var got struct{ Messages []store.Envelope }
	json.NewDecoder(resp.Body).Decode(&got)
	if len(got.Messages) != 1 || !bytes.Equal(got.Messages[0].Data, envelope) {
		t.Fatalf("fetch: %+v", got)
	}

	ack, _ := json.Marshal(map[string][]string{"ids": {got.Messages[0].ID}})
	if resp := bob.do("POST", "/v1/messages/ack", ack, true); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("ack: %d", resp.StatusCode)
	}
	resp = bob.do("GET", "/v1/messages", nil, true)
	json.NewDecoder(resp.Body).Decode(&got)
	if len(got.Messages) != 0 {
		t.Fatalf("expected empty mailbox, got %d", len(got.Messages))
	}
}

func TestAuthRejectsOtherKeyAndReplay(t *testing.T) {
	srv := newServer(t)
	bob := register(t, srv, 0)

	// Alice signing as Bob is rejected.
	mallory := register(t, srv, 0)
	mallory.id = bob.id
	if resp := mallory.do("GET", "/v1/messages", nil, true); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("forged auth: %d", resp.StatusCode)
	}

	// Replaying an identical signed request is rejected.
	ts := time.Now().Unix()
	nonce := hex.EncodeToString(randBytes(16))
	sig := ed25519.Sign(bob.priv, SigningPayload("GET", "/v1/messages", ts, nonce, nil))
	hdr := fmt.Sprintf("Calc %s:%d:%s:%s", bob.id, ts, nonce, base64.StdEncoding.EncodeToString(sig))
	for i, want := range []int{http.StatusOK, http.StatusUnauthorized} {
		req, _ := http.NewRequest("GET", srv.URL+"/v1/messages", nil)
		req.Header.Set("Authorization", hdr)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("attempt %d: %d, want %d", i, resp.StatusCode, want)
		}
	}

	// Stale timestamps are rejected.
	old := time.Now().Add(-10 * time.Minute).Unix()
	sig = ed25519.Sign(bob.priv, SigningPayload("GET", "/v1/messages", old, nonce, nil))
	req, _ := http.NewRequest("GET", srv.URL+"/v1/messages", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Calc %s:%d:%s:%s", bob.id, old, nonce, base64.StdEncoding.EncodeToString(sig)))
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("stale: %d", resp.StatusCode)
	}
}

func TestRegisterRequiresMatchingID(t *testing.T) {
	srv := newServer(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ik := append([]byte{0x05}, randBytes(32)...)
	body, _ := json.Marshal(registerRequest{
		IdentityKey: ik, AuthKey: pub,
		SealingKey:      store.SignedKey{PublicKey: randBytes(32)},
		SignedPreKey:    store.SignedKey{PublicKey: randBytes(33)},
		KyberLastResort: store.SignedKey{PublicKey: randBytes(64)},
	})
	c := &client{t: t, srv: srv, id: "someoneelse", priv: priv}
	if resp := c.do("POST", "/v1/accounts", body, true); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d", resp.StatusCode)
	}
}

func TestQueueLimitAndDelete(t *testing.T) {
	srv := newServer(t)
	bob := register(t, srv, 0)
	anon := &client{t: t, srv: srv}
	for i, want := range []int{202, 202, 202, 429} {
		if resp := anon.do("PUT", "/v1/messages/"+bob.id, []byte("x"), false); resp.StatusCode != want {
			t.Fatalf("send %d: %d, want %d", i, resp.StatusCode, want)
		}
	}
	if resp := bob.do("DELETE", "/v1/accounts", nil, true); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if resp := anon.do("PUT", "/v1/messages/"+bob.id, []byte("x"), false); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("send after delete: %d", resp.StatusCode)
	}
}
