//go:build darwin || linux

package purego

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func safeStateInfo(info os.FileInfo, directory bool) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.IsDir() != directory {
		return false
	}
	if directory {
		return info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0700
	}
	return info.Mode().IsRegular() && info.Mode().Perm() == 0600 && stat.Nlink == 1
}
func ensureStateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !safeStateInfo(info, true) {
		return errors.New("unsafe machine directory")
	}
	return nil
}
func openState(path string, flags int) (*os.File, error) {
	fd, err := syscall.Open(path, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil || !safeStateInfo(info, false) {
		f.Close()
		return nil, errors.New("unsafe machine file")
	}
	return f, nil
}
func lockState(path string) (func(), error) {
	f, err := openState(path, syscall.O_CREAT|syscall.O_RDWR)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}
func readState(path string) ([]byte, error) {
	f, err := openState(path, syscall.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(raw) == 0 || len(raw) > 65536 {
		clear(raw)
		return nil, errors.New("invalid machine state size")
	}
	return raw, nil
}
func writeState(path string, raw []byte) error {
	// State is only created once. The held lock prevents concurrent provisioning.
	// Link publishes the fully synced temporary file without replacing anything.
	f, err := os.CreateTemp(filepath.Dir(path), ".machine-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Link(f.Name(), path); err != nil {
		return err
	}
	return os.Remove(f.Name())
}
