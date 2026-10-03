// Package blobs stores encrypted attachments as files. Like envelopes they
// are opaque to the relay: the client encrypts and pads every attachment with
// a fresh key that only travels inside the end-to-end encrypted message.
//
// A blob's ID is 128 random bits chosen by the uploader and works as a
// capability: whoever knows it (sender and recipient) may fetch or delete it.
package blobs

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("already exists")
	ErrTooLarge = errors.New("too large")
	ErrFull     = errors.New("storage quota reached")
	ErrBadID    = errors.New("bad id")
	ErrEmpty    = errors.New("empty blob")
)

var idPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func ValidID(id string) bool { return idPattern.MatchString(id) }

type Store struct {
	dir     string
	ttl     time.Duration
	maxSize int64
	quota   int64
	now     func() time.Time

	mu   sync.Mutex
	used int64
}

// Open uses dir for blob files. maxSize caps a single blob, quota caps the
// sum of all blobs (a full store refuses uploads until blobs expire).
func Open(dir string, ttl time.Duration, maxSize, quota int64) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, ttl: ttl, maxSize: maxSize, quota: quota, now: time.Now}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !ValidID(e.Name()) {
			// Leftover partial upload from a crash.
			os.Remove(filepath.Join(dir, e.Name()))
			continue
		}
		if info, err := e.Info(); err == nil {
			s.used += info.Size()
		}
	}
	return s, nil
}

func (s *Store) MaxSize() int64 { return s.maxSize }

func (s *Store) path(id string) string { return filepath.Join(s.dir, id) }

// Put streams r into a new blob. Partial uploads never become visible.
func (s *Store) Put(id string, r io.Reader) error {
	if !ValidID(id) {
		return ErrBadID
	}
	if _, err := os.Stat(s.path(id)); err == nil {
		return ErrExists
	}
	s.mu.Lock()
	full := s.used+s.maxSize > s.quota
	s.mu.Unlock()
	if full {
		return ErrFull
	}

	tmp, err := os.CreateTemp(s.dir, "upload-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	n, err := io.Copy(tmp, io.LimitReader(r, s.maxSize+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > s.maxSize {
		return ErrTooLarge
	}
	if n == 0 {
		return ErrEmpty
	}
	// Link instead of rename so a concurrent upload with the same ID can't
	// overwrite an existing blob.
	if err := os.Link(tmp.Name(), s.path(id)); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrExists
		}
		return err
	}
	s.mu.Lock()
	s.used += n
	s.mu.Unlock()
	return nil
}

// Open returns the blob for reading; the caller closes it.
func (s *Store) Open(id string) (*os.File, error) {
	if !ValidID(id) {
		return nil, ErrBadID
	}
	f, err := os.Open(s.path(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return f, err
}

func (s *Store) Delete(id string) error {
	if !ValidID(id) {
		return ErrBadID
	}
	return s.remove(s.path(id))
}

func (s *Store) remove(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotFound
		}
		return err
	}
	s.mu.Lock()
	s.used -= info.Size()
	s.mu.Unlock()
	return nil
}

// PurgeExpired removes blobs older than the TTL. Returns the number removed.
func (s *Store) PurgeExpired() (int, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return 0, err
	}
	cutoff := s.now().Add(-s.ttl)
	removed := 0
	for _, e := range entries {
		if !ValidID(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		if s.remove(s.path(e.Name())) == nil {
			removed++
		}
	}
	return removed, nil
}
