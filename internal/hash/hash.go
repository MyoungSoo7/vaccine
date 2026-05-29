package hash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

type FileHashes struct {
	Path   string
	SHA256 string
	SHA1   string
	MD5    string
	Size   int64
}

func ComputeFile(path string) (*FileHashes, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	sha256h := sha256.New()
	sha1h := sha1.New()
	md5h := md5.New()
	w := io.MultiWriter(sha256h, sha1h, md5h)

	if _, err := io.Copy(w, f); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	return &FileHashes{
		Path:   path,
		SHA256: hex.EncodeToString(sha256h.Sum(nil)),
		SHA1:   hex.EncodeToString(sha1h.Sum(nil)),
		MD5:    hex.EncodeToString(md5h.Sum(nil)),
		Size:   stat.Size(),
	}, nil
}
