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

func TestFetchIsFIFOWithinOneSecond(t *testing.T) {
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
	want := []string{"offer", "ice-1", "ice-2", "ice-3", "ice-4", "hangup"}
	for _, m := range want {
		if err := s.Enqueue("a", []byte(m)); err != nil {
			t.Fatal(err)
		}
	}
	msgs, _ := s.Fetch("a", 10)
	if len(msgs) != len(want) {
		t.Fatalf("got %d messages", len(msgs))
	}
	for i, m := range msgs {
		if string(m.Data) != want[i] {
			t.Fatalf("position %d: %q, want %q", i, m.Data, want[i])
		}
	}
}
