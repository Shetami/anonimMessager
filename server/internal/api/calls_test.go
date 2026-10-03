package api

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shetami/anonimmessager/server/internal/store"
)

func TestLongPollWakesOnSend(t *testing.T) {
	srv := newServer(t)
	bob := register(t, srv, 0)
	anon := &client{t: t, srv: srv}

	type result struct {
		n       int
		elapsed time.Duration
	}
	done := make(chan result)
	go func() {
		start := time.Now()
		resp := bob.do("GET", "/v1/messages?wait=20", nil, true)
		var got struct{ Messages []store.Envelope }
		json.NewDecoder(resp.Body).Decode(&got)
		done <- result{len(got.Messages), time.Since(start)}
	}()
	time.Sleep(300 * time.Millisecond)
	if resp := anon.do("PUT", "/v1/messages/"+bob.id, []byte("ring"), false); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("send: %d", resp.StatusCode)
	}
	select {
	case r := <-done:
		if r.n != 1 || r.elapsed > 5*time.Second {
			t.Fatalf("got %d messages after %v", r.n, r.elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("long poll was not woken")
	}
}

func TestLongPollTimesOutEmpty(t *testing.T) {
	srv := newServer(t)
	bob := register(t, srv, 0)
	start := time.Now()
	resp := bob.do("GET", "/v1/messages?wait=1", nil, true)
	var got struct{ Messages []store.Envelope }
	json.NewDecoder(resp.Body).Decode(&got)
	if resp.StatusCode != http.StatusOK || len(got.Messages) != 0 {
		t.Fatalf("status %d, %d messages", resp.StatusCode, len(got.Messages))
	}
	if e := time.Since(start); e < 900*time.Millisecond || e > 5*time.Second {
		t.Fatalf("returned after %v", e)
	}
	if resp := bob.do("GET", "/v1/messages?wait=-1", nil, true); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("negative wait: %d", resp.StatusCode)
	}
}

func TestTURNCredentials(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"), time.Hour, 10)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	a := New(st, nil)
	plain := httptest.NewServer(a.Handler())
	t.Cleanup(plain.Close)
	anon := &client{t: t, srv: plain}
	if resp := anon.do("GET", "/v1/turn", nil, false); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("turn disabled: %d", resp.StatusCode)
	}

	secret := []byte("s3cret")
	a.TURN = &TURNConfig{Secret: secret, URLs: []string{"turn:turn.example.com:3478"}, TTL: time.Hour}
	resp := anon.do("GET", "/v1/turn", nil, false)
	var c turnCredentials
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("turn: %d %v", resp.StatusCode, err)
	}
	expiry, err := strconv.ParseInt(strings.SplitN(c.Username, ":", 2)[0], 10, 64)
	if err != nil || expiry < time.Now().Add(59*time.Minute).Unix() || expiry > time.Now().Add(61*time.Minute).Unix() {
		t.Fatalf("username %q", c.Username)
	}
	mac := hmac.New(sha1.New, secret)
	mac.Write([]byte(c.Username))
	if c.Password != base64.StdEncoding.EncodeToString(mac.Sum(nil)) || c.TTL != 3600 || len(c.URLs) != 1 {
		t.Fatalf("credentials: %+v", c)
	}
	// Each request gets a distinct username.
	var c2 turnCredentials
	json.NewDecoder(anon.do("GET", "/v1/turn", nil, false).Body).Decode(&c2)
	if c2.Username == c.Username {
		t.Fatal("usernames repeat")
	}
}
