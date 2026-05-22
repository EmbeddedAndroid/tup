// Package backup extracts the tar.gz produced by tufd's
// GET /api/v1/_backup. Mirrors the tufd-side reader so tup doesn't
// depend on the tufd module.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Read extracts a tar.gz from r into dataDir. Refuses entries with
// `..` or absolute paths so a tampered tarball can't write outside
// dataDir. Caller MUST ensure tufd is stopped before restore.
func Read(r io.Reader, dataDir string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar next: %w", err)
		}
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") || filepath.IsAbs(clean) {
			return fmt.Errorf("tar entry escapes dataDir: %q", hdr.Name)
		}
		dst := filepath.Join(dataDir, clean)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(hdr.Mode))
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, tr); err != nil {
			_ = f.Close()
			return err
		}
		_ = f.Close()
	}
	return nil
}
