// Package blocklist loads local SHA-256 hash blocklists from text files.
// Each line is either a 64-char hex hash or a comment (# ...) / blank.
// Used to flag known-bad hashes without hitting VirusTotal.
package blocklist

import (
	"bufio"
	"os"
	"strings"
	"sync"
)

type Blocklist struct {
	mu     sync.RWMutex
	hashes map[string]string // sha256 → source label
}

func New() *Blocklist {
	return &Blocklist{hashes: make(map[string]string)}
}

// Load reads a file of hashes. Lines starting with # are comments.
// `label` is what we tag matches with (e.g. the filename).
func (b *Blocklist) Load(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	b.mu.Lock()
	defer b.mu.Unlock()
	label := path

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Accept just the hash or "<hash> <description>"
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		h := strings.ToLower(fields[0])
		if len(h) != 64 || !isHex(h) {
			continue
		}
		b.hashes[h] = label
	}
	return sc.Err()
}

// LoadAll loads multiple files. Errors are collected; loading continues.
func (b *Blocklist) LoadAll(paths []string) []error {
	var errs []error
	for _, p := range paths {
		if err := b.Load(p); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

func (b *Blocklist) Match(sha256 string) (string, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	src, ok := b.hashes[strings.ToLower(sha256)]
	return src, ok
}

func (b *Blocklist) Size() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.hashes)
}

func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}
