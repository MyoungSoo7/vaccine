package scanner

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/MyoungSoo7/vaccine/internal/blocklist"
	"github.com/MyoungSoo7/vaccine/internal/cache"
	"github.com/MyoungSoo7/vaccine/internal/hash"
	"github.com/MyoungSoo7/vaccine/internal/virustotal"
)

type ScanResult struct {
	Path     string
	Hashes   *hash.FileHashes
	VT       *virustotal.FileReport
	CacheHit bool
	BlockHit string // non-empty when local blocklist matched
	Error    error
	Verdict  string
	Duration time.Duration
}

type Scanner struct {
	vt        *virustotal.Client
	cache     *cache.Cache
	blocklist *blocklist.Blocklist
	whitelist map[string]bool
	maxSize   int64
	rate      time.Duration
}

type Option func(*Scanner)

func WithCache(c *cache.Cache) Option       { return func(s *Scanner) { s.cache = c } }
func WithBlocklist(b *blocklist.Blocklist) Option { return func(s *Scanner) { s.blocklist = b } }
func WithMaxFileMB(mb int) Option            { return func(s *Scanner) { s.maxSize = int64(mb) * 1024 * 1024 } }
func WithRateSeconds(secs int) Option        { return func(s *Scanner) { s.rate = time.Duration(secs) * time.Second } }
func WithWhitelist(paths []string) Option {
	return func(s *Scanner) {
		s.whitelist = make(map[string]bool, len(paths))
		for _, p := range paths {
			abs, err := filepath.Abs(p)
			if err == nil {
				s.whitelist[abs] = true
			}
		}
	}
}

func New(vt *virustotal.Client, opts ...Option) *Scanner {
	s := &Scanner{
		vt:      vt,
		maxSize: 100 * 1024 * 1024,
		rate:    16 * time.Second,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// ScanFile hashes one file, then consults local blocklist + cache + VT in order.
func (s *Scanner) ScanFile(ctx context.Context, path string) ScanResult {
	start := time.Now()
	r := ScanResult{Path: path}

	if s.whitelisted(path) {
		r.Verdict = "whitelisted"
		r.Duration = time.Since(start)
		return r
	}

	h, err := hash.ComputeFile(path)
	if err != nil {
		r.Error = err
		r.Verdict = "error"
		r.Duration = time.Since(start)
		return r
	}
	r.Hashes = h

	// 1) Local blocklist — instant, no quota cost.
	if s.blocklist != nil {
		if src, ok := s.blocklist.Match(h.SHA256); ok {
			r.BlockHit = src
			r.Verdict = "malicious"
			r.Duration = time.Since(start)
			return r
		}
	}

	if h.Size > s.maxSize {
		r.Verdict = "skipped-too-large"
		r.Duration = time.Since(start)
		return r
	}

	// 2) Cache — saves quota.
	if s.cache != nil {
		if e, err := s.cache.Get(h.SHA256); err == nil {
			r.VT = &virustotal.FileReport{
				Hash:       e.SHA256,
				Found:      e.Found,
				Malicious:  e.Malicious,
				Suspicious: e.Suspicious,
				Harmless:   e.Harmless,
				Undetected: e.Undetected,
			}
			r.CacheHit = true
			r.Verdict = r.VT.Verdict()
			r.Duration = time.Since(start)
			return r
		}
	}

	// 3) VT lookup.
	rep, err := s.vt.LookupHash(ctx, h.SHA256)
	if err != nil {
		r.Error = err
		r.Verdict = "error"
		r.Duration = time.Since(start)
		return r
	}
	r.VT = rep
	r.Verdict = rep.Verdict()

	if s.cache != nil && rep != nil {
		_ = s.cache.Put(cache.Entry{
			SHA256:     h.SHA256,
			Found:      rep.Found,
			Malicious:  rep.Malicious,
			Suspicious: rep.Suspicious,
			Harmless:   rep.Harmless,
			Undetected: rep.Undetected,
			Verdict:    r.Verdict,
		})
	}

	r.Duration = time.Since(start)
	return r
}

// ScanPath dispatches between single file and recursive directory scan.
func (s *Scanner) ScanPath(ctx context.Context, path string, recursive bool) ([]ScanResult, error) {
	info, err := fileStat(path)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return []ScanResult{s.ScanFile(ctx, path)}, nil
	}

	var results []ScanResult
	walkErr := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if shouldSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if !recursive && filepath.Dir(p) != path {
			return nil
		}

		res := s.ScanFile(ctx, p)
		results = append(results, res)

		// No rate limiting when we got a cache hit or stopped before VT.
		if res.CacheHit || res.BlockHit != "" || res.Verdict == "whitelisted" || res.Verdict == "skipped-too-large" || res.Verdict == "error" {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.rate):
			return nil
		}
	})
	if walkErr != nil && !errors.Is(walkErr, context.Canceled) {
		return results, walkErr
	}
	return results, nil
}

func (s *Scanner) whitelisted(path string) bool {
	if len(s.whitelist) == 0 {
		return false
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	return s.whitelist[abs]
}

func shouldSkipDir(name string) bool {
	skip := []string{".git", "node_modules", ".venv", "venv", "__pycache__", ".cache"}
	for _, s := range skip {
		if strings.EqualFold(name, s) {
			return true
		}
	}
	return false
}
