//go:build windows

package platform

import (
	"errors"
	"os"
	"sync"

	"golang.org/x/sys/windows"
	"ipa-loader/app/internal/securestore"
)

func lockStaging(path string) (func(), error) {
	file, err := createPrivateFile(path)
	if errors.Is(err, os.ErrExist) {
		name, nameErr := windows.UTF16PtrFromString(path)
		if nameErr != nil {
			return nil, failure("Invalid installation recovery lock path")
		}
		var handle windows.Handle
		handle, err = windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err == nil {
			file = os.NewFile(uintptr(handle), path)
		}
	}
	if err != nil {
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return nil, failure("Another installation is using this iPhone. Wait for it to finish, then try again")
		}
		return nil, failure("Could not open installation recovery lock")
	}
	if err = securestore.CheckHandle(windows.Handle(file.Fd()), false); err != nil {
		file.Close()
		return nil, failure("Installation recovery lock has unsafe permissions")
	}
	var overlapped windows.Overlapped
	if err = windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped); err != nil {
		file.Close()
		return nil, failure("Another installation is using this iPhone. Wait for it to finish, then try again")
	}
	var once sync.Once
	// Keep the file in place so processes always lock the same filesystem object.
	return func() {
		once.Do(func() {
			_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped)
			_ = file.Close()
		})
	}, nil
}
