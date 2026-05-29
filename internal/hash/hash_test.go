package hash

import (
	"os"
	"path/filepath"
	"testing"
)

func TestComputeFile_KnownString(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.txt")
	if err := os.WriteFile(path, []byte("hello world"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := ComputeFile(path)
	if err != nil {
		t.Fatalf("ComputeFile: %v", err)
	}

	const wantSHA256 = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if got.SHA256 != wantSHA256 {
		t.Errorf("SHA256 = %s, want %s", got.SHA256, wantSHA256)
	}
	if got.Size != 11 {
		t.Errorf("Size = %d, want 11", got.Size)
	}
}

func TestComputeFile_NotFound(t *testing.T) {
	_, err := ComputeFile("/nonexistent/path/file.bin")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}
