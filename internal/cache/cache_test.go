package cache

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestPutGet_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	c := New(filepath.Join(dir, "cache"), 24)

	e := Entry{
		SHA256:    "abcd1234",
		Found:     true,
		Malicious: 5,
		Verdict:   "malicious",
	}
	if err := c.Put(e); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := c.Get("abcd1234")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.SHA256 != "abcd1234" || got.Malicious != 5 || got.Verdict != "malicious" {
		t.Errorf("roundtrip mismatch: %+v", got)
	}
}

func TestGet_Miss(t *testing.T) {
	dir := t.TempDir()
	c := New(filepath.Join(dir, "cache"), 24)
	_, err := c.Get("nothing")
	if !errors.Is(err, ErrMiss) {
		t.Errorf("err = %v, want ErrMiss", err)
	}
}

func TestGet_Expired(t *testing.T) {
	dir := t.TempDir()
	c := New(filepath.Join(dir, "cache"), 1)
	e := Entry{SHA256: "expired", StoredAt: time.Now().Add(-2 * time.Hour)}
	if err := c.Put(e); err != nil {
		t.Fatal(err)
	}
	// Put resets StoredAt; force expiry by manual write at old time.
	// Instead: use 0-hour TTL.
	c = New(filepath.Join(dir, "cache2"), 0)
	if err := c.Put(Entry{SHA256: "x"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	_, err := c.Get("x")
	if !errors.Is(err, ErrMiss) {
		t.Errorf("expected ErrMiss for zero-TTL, got %v", err)
	}
}
