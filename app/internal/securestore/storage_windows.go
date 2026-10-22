//go:build windows

// Package securestore protects local Windows secrets with current-user DPAPI
// and protected NTFS ACLs. It does not use machine-wide encryption or plaintext
// fallback storage.
package securestore

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const maxBlob = 16 << 20

var blobMagic = []byte("IPALDP01")
var entropy = []byte("org.example.ipaloader.windows.securestore.v1")

func blob(data []byte) windows.DataBlob {
	return windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
}

// Protect encrypts for the current Windows user, with UI prompts disabled.
func Protect(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data) > maxBlob {
		return nil, errors.New("Invalid private storage data")
	}
	in, salt := blob(data), blob(entropy)
	var out windows.DataBlob
	if windows.CryptProtectData(&in, nil, &salt, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out) != nil {
		return nil, errors.New("Windows could not protect private storage")
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	if out.Data == nil || out.Size == 0 || out.Size > maxBlob+65536 {
		return nil, errors.New("Windows returned invalid protected storage")
	}
	return append(append([]byte{}, blobMagic...), unsafe.Slice(out.Data, out.Size)...), nil
}

// Unprotect validates the format and decrypts only in the current user context.
func Unprotect(data []byte) ([]byte, error) {
	if len(data) <= len(blobMagic) || len(data) > maxBlob+65536 || !bytes.HasPrefix(data, blobMagic) {
		return nil, errors.New("Private storage format is invalid")
	}
	in, salt := blob(data[len(blobMagic):]), blob(entropy)
	var out windows.DataBlob
	if windows.CryptUnprotectData(&in, nil, &salt, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out) != nil {
		return nil, errors.New("Windows could not unlock private storage for this user")
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	if out.Data == nil || out.Size == 0 || out.Size > maxBlob {
		return nil, errors.New("Windows returned invalid private storage")
	}
	plain := unsafe.Slice(out.Data, out.Size)
	defer clear(plain)
	return append([]byte{}, plain...), nil
}

func attributes() (*windows.SecurityAttributes, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	sid := user.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")")
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, nil
}

func checkHandle(handle windows.Handle, directory bool) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory || (!directory && info.NumberOfLinks != 1) {
		return errors.New("Private storage must be an ordinary owned file or directory")
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(user.User.Sid) {
		return errors.New("Private storage has a different owner")
	}
	control, _, err := sd.Control()
	if err != nil || (directory && control&windows.SE_DACL_PROTECTED == 0) {
		return errors.New("Private storage permissions are inherited")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount != 1 {
		return errors.New("Private storage permissions are not restricted to this user")
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if windows.GetAce(acl, 0, &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || (directory && ace.Header.AceFlags&windows.INHERITED_ACE != 0) || !(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(user.User.Sid) {
		return errors.New("Private storage permissions are not restricted to this user")
	}
	runtime.KeepAlive(sd)
	return nil
}

// CheckHandle validates a handle without reopening its path. Unlike CheckFile,
// this requires a protected DACL for files too, because no parent path is
// available to validate inherited permissions.
func CheckHandle(handle windows.Handle, directory bool) error {
	if err := checkHandle(handle, directory); err != nil {
		return err
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("Private storage handle permissions are inherited")
	}
	return nil
}

func open(path string, access uint32, directory bool) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(name, access|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return windows.InvalidHandle, err
	}
	if err = checkHandle(handle, directory); err != nil {
		windows.CloseHandle(handle)
		return windows.InvalidHandle, err
	}
	return handle, nil
}

// CheckDir and CheckFile reject reparse points, foreign ownership and grants to
// another user; files must also have one hard link. Directories require a
// protected DACL. Files can inherit their sole current-user grant from a checked
// protected parent directory.
func CheckDir(path string) error {
	handle, err := open(path, 0, true)
	if err == nil {
		err = windows.CloseHandle(handle)
	}
	return err
}

func CheckFile(path string) error {
	if err := CheckDir(filepath.Dir(path)); err != nil {
		return err
	}
	handle, err := open(path, 0, false)
	if err == nil {
		err = windows.CloseHandle(handle)
	}
	return err
}

// CreatePrivate exclusively creates an ordinary file with a protected
// current-user-only DACL. It never opens or truncates an existing file.
func CreatePrivate(path string) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("Private storage requires an absolute path")
	}
	sa, err := attributes()
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	runtime.KeepAlive(sa)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

// MkdirTemp creates a new randomly named directory with a protected DACL even
// when its parent is the shared Windows temporary directory.
func MkdirTemp(parent, prefix string) (string, error) {
	if parent == "" {
		parent = os.TempDir()
	}
	if !filepath.IsAbs(parent) || filepath.Base(prefix) != prefix {
		return "", errors.New("Invalid private workspace location")
	}
	sa, err := attributes()
	if err != nil {
		return "", err
	}
	for range 10 {
		var nonce [16]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return "", err
		}
		path := filepath.Join(parent, prefix+hex.EncodeToString(nonce[:]))
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return "", err
		}
		err = windows.CreateDirectory(name, sa)
		runtime.KeepAlive(sa)
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			continue
		}
		if err != nil {
			return "", err
		}
		return path, nil
	}
	return "", errors.New("Could not create unique private workspace")
}

// EnsureDir creates new directories with a protected current-user-only DACL.
// Existing directories must already have safe ownership and permissions.
func EnsureDir(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("Private storage requires an absolute path")
	}
	if _, err := os.Lstat(path); err == nil {
		return CheckDir(path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(path)
	if _, err := os.Lstat(parent); errors.Is(err, os.ErrNotExist) {
		if err = EnsureDir(parent); err != nil {
			return err
		}
	}
	sa, err := attributes()
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	err = windows.CreateDirectory(name, sa)
	runtime.KeepAlive(sa)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	return CheckDir(path)
}

// Read decrypts an existing private file; absence means no saved value.
func Read(path string, limit int) ([]byte, error) {
	if limit <= 0 || limit > maxBlob {
		return nil, errors.New("Invalid private storage size limit")
	}
	if err := CheckDir(filepath.Dir(path)); err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil, nil
		}
		return nil, err
	}
	handle, err := open(path, windows.GENERIC_READ, false)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+65537))
	if err != nil || len(data) > limit+65536 {
		return nil, errors.New("Could not read private storage")
	}
	plain, err := Unprotect(data)
	if err != nil {
		return nil, err
	}
	if len(plain) > limit {
		clear(plain)
		return nil, errors.New("Private storage exceeds its size limit")
	}
	return plain, nil
}

// Write encrypts before writing and replaces the previous value atomically.
// The temporary file is protected at creation, rather than chmodded afterwards.
func Write(path string, data []byte) error {
	sealed, err := Protect(data)
	if err != nil {
		return err
	}
	if err = EnsureDir(filepath.Dir(path)); err != nil {
		return err
	}
	if _, err = os.Lstat(path); err == nil {
		if err = CheckFile(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), ".private-"+hex.EncodeToString(nonce[:]))
	defer os.Remove(tmp)
	sa, err := attributes()
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	runtime.KeepAlive(sa)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(handle), tmp)
	_, err = file.Write(sealed)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	dest, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(name, dest, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
