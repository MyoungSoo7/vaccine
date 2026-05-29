package virustotal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const apiBase = "https://www.virustotal.com/api/v3"

type Client struct {
	apiKey string
	http   *http.Client
}

func New(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		http:   &http.Client{Timeout: 30 * time.Second},
	}
}

type FileReport struct {
	Hash      string
	Found     bool
	Malicious int
	Suspicious int
	Harmless  int
	Undetected int
	Timeout   int
	Categories map[string]string
	Names     []string
	FirstSeen *time.Time
	LastSeen  *time.Time
	Raw       map[string]any
}

type apiResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Harmless   int `json:"harmless"`
				Undetected int `json:"undetected"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
			PopularThreatClassification struct {
				SuggestedThreatLabel string `json:"suggested_threat_label"`
				PopularThreatCategory []struct {
					Count int    `json:"count"`
					Value string `json:"value"`
				} `json:"popular_threat_category"`
			} `json:"popular_threat_classification"`
			MeaningfulName    string `json:"meaningful_name"`
			Names             []string `json:"names"`
			FirstSubmissionDate int64  `json:"first_submission_date"`
			LastAnalysisDate  int64    `json:"last_analysis_date"`
		} `json:"attributes"`
	} `json:"data"`
}

type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// LookupHash queries VirusTotal v3 for a file hash (SHA-256, SHA-1, or MD5).
// Returns Found=false (no error) when the hash is not in VT's database.
func (c *Client) LookupHash(ctx context.Context, hash string) (*FileReport, error) {
	if c.apiKey == "" {
		return nil, errors.New("VirusTotal API key not set (env VACCINE_VT_API_KEY)")
	}

	url := fmt.Sprintf("%s/files/%s", apiBase, hash)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vt request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read vt response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return &FileReport{Hash: hash, Found: false}, nil
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, errors.New("VirusTotal: 401 Unauthorized (check API key)")
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, errors.New("VirusTotal: 429 quota exceeded (free tier = 4 req/min, 500/day)")
	}
	if resp.StatusCode >= 400 {
		var ae apiError
		_ = json.Unmarshal(body, &ae)
		if ae.Error.Message != "" {
			return nil, fmt.Errorf("vt %d: %s (%s)", resp.StatusCode, ae.Error.Message, ae.Error.Code)
		}
		return nil, fmt.Errorf("vt %d", resp.StatusCode)
	}

	var ar apiResponse
	if err := json.Unmarshal(body, &ar); err != nil {
		return nil, fmt.Errorf("decode vt response: %w", err)
	}

	report := &FileReport{
		Hash:       hash,
		Found:      true,
		Malicious:  ar.Data.Attributes.LastAnalysisStats.Malicious,
		Suspicious: ar.Data.Attributes.LastAnalysisStats.Suspicious,
		Harmless:   ar.Data.Attributes.LastAnalysisStats.Harmless,
		Undetected: ar.Data.Attributes.LastAnalysisStats.Undetected,
		Timeout:    ar.Data.Attributes.LastAnalysisStats.Timeout,
		Names:      ar.Data.Attributes.Names,
	}
	if ar.Data.Attributes.FirstSubmissionDate > 0 {
		t := time.Unix(ar.Data.Attributes.FirstSubmissionDate, 0)
		report.FirstSeen = &t
	}
	if ar.Data.Attributes.LastAnalysisDate > 0 {
		t := time.Unix(ar.Data.Attributes.LastAnalysisDate, 0)
		report.LastSeen = &t
	}

	return report, nil
}

// Verdict returns "malicious", "suspicious", "clean", or "unknown".
func (r *FileReport) Verdict() string {
	if !r.Found {
		return "unknown"
	}
	if r.Malicious >= 3 {
		return "malicious"
	}
	if r.Malicious >= 1 || r.Suspicious >= 2 {
		return "suspicious"
	}
	return "clean"
}
