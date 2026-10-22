//go:build darwin && cgo

package accounts

/*
#cgo CFLAGS: -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework Security
#include <stdlib.h>
void *ipa_accounts_read(const char *service, int *length, int *status);
int ipa_accounts_write(const char *service, const void *data, int length);
int ipa_accounts_delete(const char *service);
*/
import "C"

import (
	"errors"
	"unsafe"
)

type nativeBackend struct{ service string }

func (b nativeBackend) serviceName() string {
	if b.service != "" {
		return b.service
	}
	return "org.example.ipaloader.desktop.accounts"
}

func (b nativeBackend) Read() ([]byte, error) {
	var length, status C.int
	name := C.CString(b.serviceName())
	defer C.free(unsafe.Pointer(name))
	data := C.ipa_accounts_read(name, &length, &status)
	if data != nil {
		defer C.free(data)
	}
	if status != 0 {
		return nil, errors.New("Could not read saved accounts from Keychain; unlock your login keychain and try again")
	}
	if length == 0 {
		return nil, nil
	}
	if data == nil || length < 0 || length > maxData {
		return nil, errors.New("Saved Keychain account data is invalid")
	}
	return C.GoBytes(data, length), nil
}

func (b nativeBackend) Write(data []byte) error {
	if len(data) == 0 || len(data) > maxData {
		return errors.New("Invalid saved account data")
	}
	name := C.CString(b.serviceName())
	defer C.free(unsafe.Pointer(name))
	if C.ipa_accounts_write(name, unsafe.Pointer(&data[0]), C.int(len(data))) != 0 {
		return errors.New("Could not save accounts in Keychain; unlock your login keychain and try again")
	}
	return nil
}

// Used for isolated native-vault integration checks; normal account removal
// updates the shared vault without touching other saved sessions.
func (b nativeBackend) deleteVault() error {
	name := C.CString(b.serviceName())
	defer C.free(unsafe.Pointer(name))
	if C.ipa_accounts_delete(name) != 0 {
		return errors.New("Could not remove isolated Keychain test entry")
	}
	return nil
}
