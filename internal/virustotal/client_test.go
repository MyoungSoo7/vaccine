package virustotal

import "testing"

func TestVerdict(t *testing.T) {
	tests := []struct {
		name string
		r    FileReport
		want string
	}{
		{"unknown when not found", FileReport{Found: false}, "unknown"},
		{"malicious 3+", FileReport{Found: true, Malicious: 3}, "malicious"},
		{"malicious 10", FileReport{Found: true, Malicious: 10}, "malicious"},
		{"suspicious 1 malicious", FileReport{Found: true, Malicious: 1}, "suspicious"},
		{"suspicious 2+ suspicious", FileReport{Found: true, Suspicious: 2}, "suspicious"},
		{"clean zeros", FileReport{Found: true, Harmless: 50}, "clean"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.r.Verdict(); got != tc.want {
				t.Errorf("Verdict = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestLookupHash_NoAPIKey(t *testing.T) {
	c := New("")
	_, err := c.LookupHash(nil, "abc")
	if err == nil {
		t.Error("expected error when API key empty")
	}
}
