//go:build windows

package accounts

import (
	"errors"
	"os"
	"path/filepath"

	"ipa-loader/app/internal/securestore"
)

type nativeBackend struct{ path string }

func (b nativeBackend) storagePath() (string, error) {
	if b.path != "" {
		return b.path, nil
	}
	root, err := os.UserCacheDir() // Windows LocalAppData, never roaming credentials.
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "ipa-loader", "accounts", "sessions.dpapi"), nil
}

func (b nativeBackend) Read() ([]byte, error) {
	path, err := b.storagePath()
	if err == nil {
		var data []byte
		data, err = securestore.Read(path, maxData)
		if err == nil {
			return data, nil
		}
	}
	return nil, errors.New("Could not read saved accounts from Windows secure storage")
}

func (b nativeBackend) Write(data []byte) error {
	if len(data) == 0 || len(data) > maxData {
		return errors.New("Invalid saved account data")
	}
	path, err := b.storagePath()
	if err == nil {
		err = securestore.Write(path, data)
	}
	if err != nil {
		return errors.New("Could not save accounts in Windows secure storage")
	}
	return nil
}
