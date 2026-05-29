package blocklist

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.txt")
	const goodHash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	body := "# header\n" +
		"  \n" +
		goodHash + "  hello world sample\n" +
		"00112233 too short\n" +
		"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz invalid hex\n" +
		"# trailing comment\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	bl := New()
	if err := bl.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if bl.Size() != 1 {
		t.Errorf("Size = %d, want 1 (junk lines ignored)", bl.Size())
	}
	if src, ok := bl.Match(goodHash); !ok {
		t.Error("expected match")
	} else if src != path {
		t.Errorf("label = %s, want %s", src, path)
	}
	if _, ok := bl.Match("deadbeef"); ok {
		t.Error("unexpected match for arbitrary hash")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	bl := New()
	if err := bl.Load("/nonexistent"); err == nil {
		t.Error("expected error for missing file")
	}
}
