//go:build darwin || linux

package platform

import (
	"os"
	"syscall"
)

func lockStaging(path string) (func(), error) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, failure("Could not open installation recovery lock")
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !owned(info) || !singleLink(info) || info.Mode().Perm() != 0600 {
		file.Close()
		return nil, failure("Installation recovery lock has unsafe permissions")
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, failure("Another installation is using this iPhone. Wait for it to finish, then try again")
	}
	// Never unlink the lock file: another process may already have it open.
	return func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = file.Close() }, nil
}
