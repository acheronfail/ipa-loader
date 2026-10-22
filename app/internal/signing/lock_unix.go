//go:build linux || darwin

package signing

import (
	"errors"
	"ipa-loader/app/internal/securestore"
	"os"
	"syscall"
)

const identitySuffix = ".secret"

func (v IdentityVault) locked(team string) (func(), error) {
	path, err := v.path(team)
	if err != nil {
		return nil, err
	}
	if err = securestore.EnsureDir(v.Dir); err != nil {
		return nil, err
	}
	lock := path + ".lock"
	fd, err := syscall.Open(lock, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errors.New("Could not open signing identity lock")
	}
	file := os.NewFile(uintptr(fd), lock)
	if err = securestore.CheckOpenFile(file); err != nil {
		file.Close()
		return nil, err
	}
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		file.Close()
		return nil, errors.New("Another operation is using this signing identity")
	}
	return func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = file.Close() }, nil
}
