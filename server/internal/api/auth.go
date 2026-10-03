package api

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Requests to a mailbox owner's endpoints carry
//
//	Authorization: Calc <accountID>:<unixSeconds>:<nonce>:<base64(ed25519 signature)>
//
// where the signature covers SigningPayload(method, path, ts, nonce, body). The
// random nonce keeps identical requests within one second distinguishable for
// the replay cache (Ed25519 signatures are deterministic). The auth
// key is an Ed25519 key that is separate from the Signal identity key and only
// ever proves mailbox ownership to the relay.
const authScheme = "Calc "

const clockSkew = 2 * time.Minute

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// AccountID derives the mailbox ID from the serialized identity public key.
// Clients compute the same value, so a contact ID shared out-of-band commits
// to the identity key and the relay cannot substitute one.
func AccountID(identityKey []byte) string {
	sum := sha256.Sum256(identityKey)
	return strings.ToLower(b32.EncodeToString(sum[:20]))
}

func SigningPayload(method, path string, ts int64, nonce string, body []byte) []byte {
	h := sha256.Sum256(body)
	return []byte(method + "\n" + path + "\n" + strconv.FormatInt(ts, 10) + "\n" + nonce + "\n" + hex.EncodeToString(h[:]))
}

type parsedAuth struct {
	id    string
	ts    int64
	nonce string
	sig   []byte
}

func parseAuth(r *http.Request) (parsedAuth, error) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, authScheme) {
		return parsedAuth{}, errors.New("missing auth")
	}
	parts := strings.Split(strings.TrimPrefix(h, authScheme), ":")
	if len(parts) != 4 || len(parts[2]) < 16 || len(parts[2]) > 64 {
		return parsedAuth{}, errors.New("malformed auth")
	}
	ts, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return parsedAuth{}, errors.New("malformed auth")
	}
	sig, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return parsedAuth{}, errors.New("malformed auth")
	}
	return parsedAuth{id: parts[0], ts: ts, nonce: parts[2], sig: sig}, nil
}

// replayCache remembers signatures seen inside the clock-skew window so a
// captured request cannot be replayed.
type replayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newReplayCache() *replayCache { return &replayCache{seen: map[string]time.Time{}} }

func (c *replayCache) checkAndAdd(sig []byte, now time.Time) bool {
	key := string(sig)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.seen) > 100_000 {
		for k, t := range c.seen {
			if now.Sub(t) > 2*clockSkew {
				delete(c.seen, k)
			}
		}
	}
	if _, ok := c.seen[key]; ok {
		return false
	}
	c.seen[key] = now
	return true
}

func verify(authKey []byte, a parsedAuth, method, path string, body []byte, now time.Time) error {
	if len(authKey) != ed25519.PublicKeySize {
		return errors.New("bad auth key size")
	}
	d := now.Sub(time.Unix(a.ts, 0))
	if d > clockSkew || d < -clockSkew {
		return fmt.Errorf("clock skew %s", d.Round(time.Second))
	}
	if !ed25519.Verify(authKey, SigningPayload(method, path, a.ts, a.nonce, body), a.sig) {
		return errors.New("bad signature")
	}
	return nil
}
