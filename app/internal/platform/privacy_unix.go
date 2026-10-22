//go:build !windows

package platform

import (
	"os"
	"path/filepath"
)

func privateFile(_ string, info os.FileInfo) bool {
	return info.Mode().IsRegular() && owned(info) && singleLink(info) && info.Mode().Perm() == 0600
}

func privateDirectory(_ string, info os.FileInfo) bool {
	return info.IsDir() && info.Mode()&os.ModeSymlink == 0 && owned(info) && info.Mode().Perm() == 0700
}

func ensurePrivateDirectory(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if !privateDirectory(path, info) {
			return failure("Private signing directory permissions are invalid")
		}
		return nil
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return failure("Could not create private signing directory")
	}
	return nil
}

func createPrivateFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
}

func privateTempDir(parent, prefix string) (string, error) {
	dir, err := os.MkdirTemp(parent, prefix)
	if err != nil {
		return "", err
	}
	// macOS's standard temporary root uses /var -> /private/var. Canonicalize
	// our newly created directory before the strict private-path checks.
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		os.Remove(dir)
		return "", err
	}
	return resolved, nil
}
