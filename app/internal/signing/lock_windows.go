//go:build windows

package signing

import (
	"errors"
	"golang.org/x/sys/windows"
	"ipa-loader/app/internal/securestore"
	"os"
)

const identitySuffix = ".dpapi"

func (v IdentityVault) locked(team string) (func(), error) {
	path, err := v.path(team)
	if err != nil {
		return nil, err
	}
	if err = securestore.EnsureDir(v.Dir); err != nil {
		return nil, errors.New("Could not prepare private Windows signing storage")
	}
	lock := path + ".lock"
	file, err := securestore.CreatePrivate(lock)
	if errors.Is(err, os.ErrExist) {
		name, pathErr := windows.UTF16PtrFromString(lock)
		if pathErr != nil {
			return nil, pathErr
		}
		handle, openErr := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if openErr != nil {
			return nil, errors.New("Windows signing storage is busy or unavailable")
		}
		file = os.NewFile(uintptr(handle), lock)
		err = securestore.CheckHandle(handle, false)
		if err != nil {
			file.Close()
			return nil, errors.New("Windows signing storage lock has unsafe permissions")
		}
	}
	if err != nil {
		return nil, errors.New("Could not lock Windows signing storage")
	}
	var overlap windows.Overlapped
	if windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlap) != nil {
		file.Close()
		return nil, errors.New("Another operation is using this Windows signing identity")
	}
	return func() {
		_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlap)
		_ = file.Close()
	}, nil
}
