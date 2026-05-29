// Package cache stores VirusTotal hash lookups on disk so repeated scans
// don't burn the (4 req/min, 500/day) free quota.
//
// Layout: one JSON file per SHA-256, name = first 2 chars / remaining
//
//	<cache_dir>/ab/cdef...123.json
package cache

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

type Entry struct {
	SHA256     string    `json:"sha256"`
	Found      bool      `json:"found"`
	Malicious  int       `json:"malicious"`
	Suspicious int       `json:"suspicious"`
	Harmless   int       `json:"harmless"`
	Undetected int       `json:"undetected"`
	Verdict    string    `json:"verdict"`
	StoredAt   time.Time `json:"stored_at"`
}

type Cache struct {
	dir string
	ttl time.Duration
}

func New(dir string, ttlHours int) *Cache {
	return &Cache{dir: dir, ttl: time.Duration(ttlHours) * time.Hour}
}

// ErrMiss is returned when there is no fresh entry for the hash.
var ErrMiss = errors.New("cache miss")

func (c *Cache) Get(sha256 string) (*Entry, error) {
	path := c.path(sha256)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrMiss
		}
		return nil, err
	}
	var e Entry
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, err
	}
	if time.Since(e.StoredAt) > c.ttl {
		_ = os.Remove(path)
		return nil, ErrMiss
	}
	return &e, nil
}

func (c *Cache) Put(e Entry) error {
	e.StoredAt = time.Now()
	path := c.path(e.SHA256)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func (c *Cache) path(sha256 string) string {
	if len(sha256) < 4 {
		return filepath.Join(c.dir, sha256+".json")
	}
	return filepath.Join(c.dir, sha256[:2], sha256[2:]+".json")
}
