//go:build (!darwin || !cgo) && !windows && !linux

package accounts

import "errors"

type nativeBackend struct{}

func (nativeBackend) Read() ([]byte, error) {
	return nil, errors.New("Secure account storage is not available on this platform yet")
}
func (nativeBackend) Write([]byte) error {
	return errors.New("Secure account storage is not available on this platform yet")
}
