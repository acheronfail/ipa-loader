//go:build linux

package accounts

import (
	"ipa-loader/app/internal/securestore"
	"os"
	"path/filepath"
)

type nativeBackend struct{ path string }

func (b nativeBackend) storagePath() (string, error) {
	if b.path != "" {
		return b.path, nil
	}
	root, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "ipa-loader", "accounts", "sessions.secret"), nil
}
func (b nativeBackend) Read() ([]byte, error) {
	path, err := b.storagePath()
	if err != nil {
		return nil, err
	}
	return securestore.Read(path, maxData)
}
func (b nativeBackend) Write(data []byte) error {
	path, err := b.storagePath()
	if err != nil {
		return err
	}
	return securestore.Write(path, data)
}
