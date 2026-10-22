//go:build darwin && !cgo

package securestore

import "errors"

func Read(string, int) ([]byte, error) {
	return nil, errors.New("Keychain storage requires a native macOS build")
}
func Write(string, []byte) error { return errors.New("Keychain storage requires a native macOS build") }
