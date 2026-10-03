// Package store persists relay state. The relay is "blind": it only ever sees
// public keys and opaque sealed envelopes addressed to random-looking mailbox IDs.
// No phone numbers, no IP addresses, no sender identities are stored.
package store

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	ErrNotFound  = errors.New("not found")
	ErrExists    = errors.New("already exists")
	ErrQueueFull = errors.New("mailbox full")
)

var (
	bAccounts = []byte("accounts")
	bPreKeys  = []byte("prekeys")  // per-account sub-bucket: one-time EC prekeys
	bKyber    = []byte("kyber")    // per-account sub-bucket: one-time Kyber prekeys
	bMessages = []byte("messages") // per-account sub-bucket: sealed envelopes
)

// SignedKey is a public key plus a signature made with the account identity key.
// The relay never verifies these signatures; clients do, which is what protects
// against a malicious relay substituting keys.
type SignedKey struct {
	ID        uint32 `json:"id"`
	PublicKey []byte `json:"publicKey"`
	Signature []byte `json:"signature,omitempty"`
}

type Account struct {
	ID              string    `json:"id"`
	IdentityKey     []byte    `json:"identityKey"`
	AuthKey         []byte    `json:"authKey"`
	RegistrationID  uint32    `json:"registrationId"`
	SealingKey      SignedKey `json:"sealingKey"`
	SignedPreKey    SignedKey `json:"signedPreKey"`
	KyberLastResort SignedKey `json:"kyberLastResort"`
}

// Bundle is what a sender fetches to start a session.
type Bundle struct {
	IdentityKey    []byte     `json:"identityKey"`
	RegistrationID uint32     `json:"registrationId"`
	SealingKey     SignedKey  `json:"sealingKey"`
	SignedPreKey   SignedKey  `json:"signedPreKey"`
	PreKey         *SignedKey `json:"preKey,omitempty"`
	KyberPreKey    SignedKey  `json:"kyberPreKey"`
}

type Envelope struct {
	ID   string `json:"id"`
	Data []byte `json:"data"`
}

type Store struct {
	db       *bolt.DB
	ttl      time.Duration
	maxQueue int
	now      func() time.Time
}

func Open(path string, ttl time.Duration, maxQueue int) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bAccounts, bPreKeys, bKyber, bMessages} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, ttl: ttl, maxQueue: maxQueue, now: time.Now}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) CreateAccount(a Account, preKeys, kyber []SignedKey) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		accounts := tx.Bucket(bAccounts)
		if accounts.Get([]byte(a.ID)) != nil {
			return ErrExists
		}
		raw, err := json.Marshal(a)
		if err != nil {
			return err
		}
		if err := accounts.Put([]byte(a.ID), raw); err != nil {
			return err
		}
		if err := putKeys(tx.Bucket(bPreKeys), a.ID, preKeys); err != nil {
			return err
		}
		return putKeys(tx.Bucket(bKyber), a.ID, kyber)
	})
}

func (s *Store) Account(id string) (Account, error) {
	var a Account
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bAccounts).Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		return json.Unmarshal(raw, &a)
	})
	return a, err
}

// UpdateKeys rotates the signed prekey / last-resort keys (when non-nil) and
// appends fresh one-time prekeys.
func (s *Store) UpdateKeys(id string, signed, kyberLastResort *SignedKey, preKeys, kyber []SignedKey) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		accounts := tx.Bucket(bAccounts)
		raw := accounts.Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		var a Account
		if err := json.Unmarshal(raw, &a); err != nil {
			return err
		}
		if signed != nil {
			a.SignedPreKey = *signed
		}
		if kyberLastResort != nil {
			a.KyberLastResort = *kyberLastResort
		}
		raw, err := json.Marshal(a)
		if err != nil {
			return err
		}
		if err := accounts.Put([]byte(id), raw); err != nil {
			return err
		}
		if err := putKeys(tx.Bucket(bPreKeys), id, preKeys); err != nil {
			return err
		}
		return putKeys(tx.Bucket(bKyber), id, kyber)
	})
}

func (s *Store) KeyCounts(id string) (preKeys, kyber int, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(bAccounts).Get([]byte(id)) == nil {
			return ErrNotFound
		}
		preKeys = subLen(tx.Bucket(bPreKeys), id)
		kyber = subLen(tx.Bucket(bKyber), id)
		return nil
	})
	return
}

// TakeBundle returns a prekey bundle, consuming one one-time EC prekey and one
// one-time Kyber prekey when available (falling back to the last-resort key).
func (s *Store) TakeBundle(id string) (Bundle, error) {
	var b Bundle
	err := s.db.Update(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bAccounts).Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		var a Account
		if err := json.Unmarshal(raw, &a); err != nil {
			return err
		}
		b = Bundle{
			IdentityKey:    a.IdentityKey,
			RegistrationID: a.RegistrationID,
			SealingKey:     a.SealingKey,
			SignedPreKey:   a.SignedPreKey,
			KyberPreKey:    a.KyberLastResort,
		}
		pk, err := popKey(tx.Bucket(bPreKeys), id)
		if err != nil {
			return err
		}
		b.PreKey = pk
		kk, err := popKey(tx.Bucket(bKyber), id)
		if err != nil {
			return err
		}
		if kk != nil {
			b.KyberPreKey = *kk
		}
		return nil
	})
	return b, err
}

func (s *Store) DeleteAccount(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(bAccounts).Get([]byte(id)) == nil {
			return ErrNotFound
		}
		if err := tx.Bucket(bAccounts).Delete([]byte(id)); err != nil {
			return err
		}
		for _, name := range [][]byte{bPreKeys, bKyber, bMessages} {
			if err := deleteSub(tx.Bucket(name), id); err != nil {
				return err
			}
		}
		return nil
	})
}

// Enqueue stores a sealed envelope for a mailbox. Message keys are
// expiry(8 bytes BE) || random(8 bytes), so iteration order is FIFO and the
// janitor can stop at the first non-expired key.
func (s *Store) Enqueue(id string, data []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(bAccounts).Get([]byte(id)) == nil {
			return ErrNotFound
		}
		q, err := tx.Bucket(bMessages).CreateBucketIfNotExists([]byte(id))
		if err != nil {
			return err
		}
		if countKeys(q, s.maxQueue) >= s.maxQueue {
			return ErrQueueFull
		}
		key := make([]byte, 16)
		binary.BigEndian.PutUint64(key, uint64(s.now().Add(s.ttl).Unix()))
		if _, err := rand.Read(key[8:]); err != nil {
			return err
		}
		return q.Put(key, data)
	})
}

func (s *Store) Fetch(id string, limit int) ([]Envelope, error) {
	var out []Envelope
	err := s.db.View(func(tx *bolt.Tx) error {
		q := tx.Bucket(bMessages).Bucket([]byte(id))
		if q == nil {
			return nil
		}
		c := q.Cursor()
		for k, v := c.First(); k != nil && len(out) < limit; k, v = c.Next() {
			out = append(out, Envelope{ID: encodeID(k), Data: append([]byte(nil), v...)})
		}
		return nil
	})
	return out, err
}

func (s *Store) Ack(id string, msgIDs []string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		q := tx.Bucket(bMessages).Bucket([]byte(id))
		if q == nil {
			return nil
		}
		for _, m := range msgIDs {
			k, ok := decodeID(m)
			if !ok {
				continue
			}
			if err := q.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// PurgeExpired removes envelopes past their TTL. Returns the number removed.
func (s *Store) PurgeExpired() (int, error) {
	now := uint64(s.now().Unix())
	removed := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bMessages).ForEachBucket(func(name []byte) error {
			q := tx.Bucket(bMessages).Bucket(name)
			c := q.Cursor()
			for k, _ := c.First(); k != nil; k, _ = c.First() {
				if binary.BigEndian.Uint64(k[:8]) > now {
					break
				}
				if err := c.Delete(); err != nil {
					return err
				}
				removed++
			}
			return nil
		})
	})
	return removed, err
}

func putKeys(parent *bolt.Bucket, id string, keys []SignedKey) error {
	if len(keys) == 0 {
		return nil
	}
	b, err := parent.CreateBucketIfNotExists([]byte(id))
	if err != nil {
		return err
	}
	for _, k := range keys {
		raw, err := json.Marshal(k)
		if err != nil {
			return err
		}
		key := make([]byte, 4)
		binary.BigEndian.PutUint32(key, k.ID)
		if err := b.Put(key, raw); err != nil {
			return err
		}
	}
	return nil
}

func popKey(parent *bolt.Bucket, id string) (*SignedKey, error) {
	b := parent.Bucket([]byte(id))
	if b == nil {
		return nil, nil
	}
	k, v := b.Cursor().First()
	if k == nil {
		return nil, nil
	}
	var sk SignedKey
	if err := json.Unmarshal(v, &sk); err != nil {
		return nil, err
	}
	return &sk, b.Delete(k)
}

func subLen(parent *bolt.Bucket, id string) int {
	b := parent.Bucket([]byte(id))
	if b == nil {
		return 0
	}
	return countKeys(b, -1)
}

// countKeys counts keys up to limit (-1 = no limit). bbolt's Stats() does not
// reflect uncommitted writes, so count with a cursor instead.
func countKeys(b *bolt.Bucket, limit int) int {
	n := 0
	c := b.Cursor()
	for k, _ := c.First(); k != nil && (limit < 0 || n < limit); k, _ = c.Next() {
		n++
	}
	return n
}

func deleteSub(parent *bolt.Bucket, id string) error {
	if parent.Bucket([]byte(id)) == nil {
		return nil
	}
	return parent.DeleteBucket([]byte(id))
}
