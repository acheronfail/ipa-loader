//go:build darwin && cgo

package securestore

/*
#cgo CFLAGS: -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework Security
#include <stdlib.h>
void *ipa_signing_read(const char *, int *, int *);
int ipa_signing_write(const char *, const void *, int);
*/
import "C"
import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"unsafe"
)

func recordName(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("absolute private record path required")
	}
	sum := sha256.Sum256([]byte(stableRecordPath(filepath.Clean(path))))
	return "org.example.ipaloader.signing." + hex.EncodeToString(sum[:]), nil
}
func Read(path string, limit int) ([]byte, error) {
	if limit <= 0 || limit > 2<<20 {
		return nil, errors.New("invalid Keychain record bound")
	}
	name, e := recordName(path)
	if e != nil {
		return nil, e
	}
	c := C.CString(name)
	defer C.free(unsafe.Pointer(c))
	var size, status C.int
	p := C.ipa_signing_read(c, &size, &status)
	if p != nil {
		defer C.free(p)
	}
	if status != 0 {
		return nil, errors.New("could not read signing material from Keychain")
	}
	if size == 0 {
		return nil, nil
	}
	if size < 0 || int(size) > limit || p == nil {
		return nil, errors.New("invalid Keychain signing material")
	}
	return C.GoBytes(p, size), nil
}
func Write(path string, data []byte) error {
	if len(data) == 0 || len(data) > 2<<20 {
		return errors.New("invalid signing record size")
	}
	name, e := recordName(path)
	if e != nil {
		return e
	}
	c := C.CString(name)
	defer C.free(unsafe.Pointer(c))
	if C.ipa_signing_write(c, unsafe.Pointer(&data[0]), C.int(len(data))) != 0 {
		return errors.New("could not protect signing material in Keychain")
	}
	return nil
}
