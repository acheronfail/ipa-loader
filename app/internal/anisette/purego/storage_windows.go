//go:build windows

package purego

import (
	"errors"
	"golang.org/x/sys/windows"
	"ipa-loader/app/internal/securestore"
	"os"
)

func ensureStateDir(path string) error         { return securestore.EnsureDir(path) }
func readState(path string) ([]byte, error)    { return securestore.Read(path, 65536) }
func writeState(path string, raw []byte) error { return securestore.Write(path, raw) }
func lockState(path string) (func(), error) {
	f, err := securestore.CreatePrivate(path)
	if errors.Is(err, os.ErrExist) {
		name, e := windows.UTF16PtrFromString(path)
		if e != nil {
			return nil, e
		}
		h, e := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		err = e
		if err == nil {
			f = os.NewFile(uintptr(h), path)
		}
	}
	if err != nil {
		return nil, err
	}
	if err = securestore.CheckHandle(windows.Handle(f.Fd()), false); err != nil {
		f.Close()
		return nil, err
	}
	var overlap windows.Overlapped
	if err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlap); err != nil {
		f.Close()
		return nil, err
	}
	return func() { _ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &overlap); _ = f.Close() }, nil
}
