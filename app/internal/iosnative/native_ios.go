//go:build ios

package iosnative

/*
#cgo CFLAGS: -fobjc-arc
#cgo LDFLAGS: -framework UIKit -framework QuartzCore -framework Foundation -framework UniformTypeIdentifiers -framework NetworkExtension
#include <stdlib.h>
char *ipa_ios_connection_settings(int builtin, const char *address, int *failed);
int ipa_ios_choose_option(const char *title, const char *json, int selected);
int ipa_ios_has_vpn(void);
char *ipa_ios_connect_vpn(void);
int ipa_ios_vpn_connected(void);
void ipa_ios_vpn_invalidate(void);
int ipa_ios_disconnect_vpn(void);
char *ipa_ios_home(void);
char *ipa_ios_bundle(void);
char *ipa_ios_choose(int *failed);
unsigned long ipa_ios_begin(void);
void ipa_ios_end(unsigned long task);
*/
import "C"
import (
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"unsafe"
)

func Home() string {
	p := C.ipa_ios_home()
	defer C.free(unsafe.Pointer(p))
	home := C.GoString(p)
	if resolved, err := filepath.EvalSymlinks(home); err == nil {
		return resolved
	}
	return home
}
func BundleID() string {
	p := C.ipa_ios_bundle()
	defer C.free(unsafe.Pointer(p))
	return C.GoString(p)
}
func ChooseIPA() (string, error) {
	var failed C.int
	p := C.ipa_ios_choose(&failed)
	if p != nil {
		defer C.free(unsafe.Pointer(p))
	}
	if failed != 0 {
		return "", errors.New("Could not import the IPA. Choose a downloaded IPA from Files")
	}
	if p == nil {
		return "", nil
	}
	return C.GoString(p), nil
}
func BeginTask() func() { task := C.ipa_ios_begin(); return func() { C.ipa_ios_end(task) } }

var vpnMu sync.Mutex

func HasVPN() bool { return C.ipa_ios_has_vpn() != 0 }
func ResetVPN()    { C.ipa_ios_vpn_invalidate() }
func VPNState() (bool, bool) {
	if !HasVPN() {
		return false, false
	}
	return true, C.ipa_ios_vpn_connected() != 0
}
func SetVPN(on bool) error {
	vpnMu.Lock()
	defer vpnMu.Unlock()
	if !HasVPN() {
		return errors.New("This build does not include the local VPN")
	}
	if !on {
		if C.ipa_ios_disconnect_vpn() == 0 {
			return errors.New("Local VPN is still disconnecting. Check its status in Settings")
		}
		return nil
	}
	p := C.ipa_ios_connect_vpn()
	if p == nil {
		return nil
	}
	defer C.free(unsafe.Pointer(p))
	return errors.New(C.GoString(p))
}
func ConnectVPN() error {
	if !HasVPN() {
		return nil
	}
	if C.ipa_ios_vpn_connected() != 0 {
		return nil
	}
	return errors.New("Enable Local VPN in Settings to install, refresh, or check apps")
}

func ChooseOption(title string, options []string, selected int) (int, error) {
	raw, err := json.Marshal(options)
	if err != nil {
		return -1, err
	}
	ctitle := C.CString(title)
	defer C.free(unsafe.Pointer(ctitle))
	coptions := C.CString(string(raw))
	defer C.free(unsafe.Pointer(coptions))
	index := int(C.ipa_ios_choose_option(ctitle, coptions, C.int(selected)))
	if index < -1 {
		return -1, errors.New("Could not open the selection list. Please try again")
	}
	return index, nil
}

func ConnectionSettings(builtin bool, address string) (string, bool, error) {
	caddress := C.CString(address)
	defer C.free(unsafe.Pointer(caddress))
	var cbuiltin C.int
	if builtin {
		cbuiltin = 1
	}
	var failed C.int
	p := C.ipa_ios_connection_settings(cbuiltin, caddress, &failed)
	if failed != 0 {
		return "", false, errors.New("Could not open connection settings. Please try again")
	}
	if p == nil {
		return "", false, nil
	}
	defer C.free(unsafe.Pointer(p))
	return C.GoString(p), true, nil
}
