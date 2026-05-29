// Package intel pulls free threat-intelligence feeds and exposes
// match-by-host / match-by-url helpers.
//
// URLhaus (abuse.ch) — free, no auth, CSV format.
package intel

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type URLhausEntry struct {
	ID         string
	DateAdded  string
	URL        string
	Status     string
	Threat     string
	Tags       string
	Reporter   string
	URLhausLink string
}

type URLhausFeed struct {
	mu      sync.RWMutex
	byHost  map[string][]URLhausEntry
	byURL   map[string]URLhausEntry
	loaded  time.Time
	feedURL string
}

func NewURLhaus(feedURL string) *URLhausFeed {
	return &URLhausFeed{
		byHost:  make(map[string][]URLhausEntry),
		byURL:   make(map[string]URLhausEntry),
		feedURL: feedURL,
	}
}

// Refresh downloads the CSV and rebuilds the in-memory indexes.
func (f *URLhausFeed) Refresh(ctx context.Context) error {
	if f.feedURL == "" {
		return errors.New("urlhaus feed URL not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.feedURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "vaccine/0.1 (+https://github.com/MyoungSoo7/vaccine)")
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("urlhaus fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("urlhaus status %d", resp.StatusCode)
	}

	byHost := make(map[string][]URLhausEntry)
	byURL := make(map[string]URLhausEntry)

	r := csv.NewReader(skipComments(resp.Body))
	r.LazyQuotes = true
	r.FieldsPerRecord = -1
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(rec) < 8 {
			continue
		}
		e := URLhausEntry{
			ID:         strings.TrimSpace(rec[0]),
			DateAdded:  strings.TrimSpace(rec[1]),
			URL:        strings.TrimSpace(rec[2]),
			Status:     strings.TrimSpace(rec[3]),
			Threat:     strings.TrimSpace(rec[4]),
			Tags:       strings.TrimSpace(rec[5]),
			Reporter:   strings.TrimSpace(rec[6]),
			URLhausLink: strings.TrimSpace(rec[7]),
		}
		byURL[strings.ToLower(e.URL)] = e
		if u, err := url.Parse(e.URL); err == nil && u.Host != "" {
			h := strings.ToLower(u.Hostname())
			byHost[h] = append(byHost[h], e)
		}
	}

	f.mu.Lock()
	f.byHost = byHost
	f.byURL = byURL
	f.loaded = time.Now()
	f.mu.Unlock()
	return nil
}

func (f *URLhausFeed) MatchHost(host string) ([]URLhausEntry, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	entries, ok := f.byHost[strings.ToLower(host)]
	return entries, ok && len(entries) > 0
}

func (f *URLhausFeed) MatchURL(rawURL string) (URLhausEntry, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	e, ok := f.byURL[strings.ToLower(rawURL)]
	return e, ok
}

func (f *URLhausFeed) Size() (urls, hosts int) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.byURL), len(f.byHost)
}

func (f *URLhausFeed) LastLoaded() time.Time {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.loaded
}

// skipComments wraps r so the CSV reader doesn't choke on lines starting with #.
func skipComments(r io.Reader) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		buf := make([]byte, 64*1024)
		var carry []byte
		for {
			n, err := r.Read(buf)
			if n > 0 {
				carry = append(carry, buf[:n]...)
				for {
					i := indexByte(carry, '\n')
					if i < 0 {
						break
					}
					line := carry[:i+1]
					carry = carry[i+1:]
					trim := trimLeadingSpace(line)
					if len(trim) == 0 || trim[0] == '#' {
						continue
					}
					if _, werr := pw.Write(line); werr != nil {
						return
					}
				}
			}
			if err == io.EOF {
				if len(carry) > 0 {
					trim := trimLeadingSpace(carry)
					if len(trim) > 0 && trim[0] != '#' {
						_, _ = pw.Write(carry)
					}
				}
				return
			}
			if err != nil {
				_ = pw.CloseWithError(err)
				return
			}
		}
	}()
	return pr
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func trimLeadingSpace(b []byte) []byte {
	for i := range b {
		if b[i] != ' ' && b[i] != '\t' {
			return b[i:]
		}
	}
	return nil
}
