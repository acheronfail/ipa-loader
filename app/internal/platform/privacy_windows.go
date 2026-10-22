//go:build windows

package platform

import (
	"os"

	"ipa-loader/app/internal/securestore"
)

// Windows os.FileMode permission bits do not describe NTFS access control.
// Check the handle's owner, DACL, reparse status and hard-link count instead.
func privateFile(path string, info os.FileInfo) bool {
	return info.Mode().IsRegular() && securestore.CheckFile(path) == nil
}

func privateDirectory(path string, info os.FileInfo) bool {
	return info.IsDir() && securestore.CheckDir(path) == nil
}

func ensurePrivateDirectory(path string) error {
	if err := securestore.EnsureDir(path); err != nil {
		return failure("Private signing directory permissions are invalid")
	}
	return nil
}

func createPrivateFile(path string) (*os.File, error) { return securestore.CreatePrivate(path) }
func privateTempDir(parent, prefix string) (string, error) {
	return securestore.MkdirTemp(parent, prefix)
}
