//go:build linux || darwin

package securestore

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func checked(info os.FileInfo, directory bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode()&0077 != 0 || info.IsDir() != directory || (!directory && (!info.Mode().IsRegular() || stat.Nlink != 1)) {
		return errors.New("Private storage has unsafe ownership, permissions or file type")
	}
	return nil
}
func CheckDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Private directory cannot be a symlink")
	}
	return checked(info, true)
}
func CheckFile(path string) error {
	file, err := openPrivate(path, syscall.O_RDONLY)
	if err != nil {
		return err
	}
	return file.Close()
}
func openPrivate(path string, flags int) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("Private storage requires an absolute path")
	}
	fd, err := syscall.Open(path, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err == nil {
		err = checked(info, false)
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}
func CreatePrivate(path string) (*os.File, error) {
	return openPrivate(path, syscall.O_CREAT|syscall.O_EXCL|syscall.O_RDWR)
}
func EnsureDir(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("Private storage requires an absolute path")
	}
	// Reject symlink ancestors as well as a linked leaf.
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		if info, err := os.Lstat(p); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return errors.New("Private path cannot contain symlinks")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		if err = os.MkdirAll(path, 0700); err != nil {
			return err
		}
	}
	return CheckDir(path)
}
func MkdirTemp(parent, prefix string) (string, error) {
	if parent != "" && !filepath.IsAbs(parent) {
		return "", errors.New("Private workspace requires an absolute path")
	}
	path, err := os.MkdirTemp(parent, prefix)
	if err == nil {
		err = CheckDir(path)
	}
	if err != nil && path != "" {
		os.Remove(path)
	}
	return path, err
}

// CheckOpenFile validates the exact open descriptor used for a private lock.
func CheckOpenFile(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	return checked(info, false)
}
