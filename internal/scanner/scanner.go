package scanner

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/MyoungSoo7/vaccine/internal/hash"
	"github.com/MyoungSoo7/vaccine/internal/virustotal"
)

type ScanResult struct {
	Path      string
	Hashes    *hash.FileHashes
	VT        *virustotal.FileReport
	Error     error
	Verdict   string
	Duration  time.Duration
}

type Scanner struct {
	vt      *virustotal.Client
	maxSize int64
	rate    time.Duration
}

func New(vt *virustotal.Client) *Scanner {
	return &Scanner{
		vt:      vt,
		maxSize: 100 * 1024 * 1024,
		rate:    16 * time.Second,
	}
}

// ScanFile hashes one file and queries VirusTotal.
func (s *Scanner) ScanFile(ctx context.Context, path string) ScanResult {
	start := time.Now()
	r := ScanResult{Path: path}

	h, err := hash.ComputeFile(path)
	if err != nil {
		r.Error = err
		r.Verdict = "error"
		r.Duration = time.Since(start)
		return r
	}
	r.Hashes = h

	if h.Size > s.maxSize {
		r.Verdict = "skipped-too-large"
		r.Duration = time.Since(start)
		return r
	}

	rep, err := s.vt.LookupHash(ctx, h.SHA256)
	if err != nil {
		r.Error = err
		r.Verdict = "error"
		r.Duration = time.Since(start)
		return r
	}
	r.VT = rep
	r.Verdict = rep.Verdict()
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

		results = append(results, s.ScanFile(ctx, p))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.rate):
			return nil
		}
	})
	if walkErr != nil && walkErr != context.Canceled {
		return results, walkErr
	}
	return results, nil
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
