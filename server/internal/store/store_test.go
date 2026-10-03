package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestPurgeExpired(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "db"), time.Hour, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreateAccount(Account{ID: "a"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	s.now = func() time.Time { return base }
	s.Enqueue("a", []byte("old"))
	s.now = func() time.Time { return base.Add(30 * time.Minute) }
	s.Enqueue("a", []byte("new"))

	s.now = func() time.Time { return base.Add(61 * time.Minute) }
	n, err := s.PurgeExpired()
	if err != nil || n != 1 {
		t.Fatalf("purged %d, err %v", n, err)
	}
	msgs, _ := s.Fetch("a", 10)
	if len(msgs) != 1 || string(msgs[0].Data) != "new" {
		t.Fatalf("remaining: %+v", msgs)
	}
}
