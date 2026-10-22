//go:build ios

package iosnative

/*
#include <stdlib.h>
void ipa_ios_apps_busy(int busy);
void ipa_ios_apps_authenticated(int authenticated);
void ipa_ios_apps_update(const char *json);
*/
import "C"
import (
	"encoding/json"
	"sync"
	"unsafe"
)

var appsLoadMu sync.Mutex

var appsHandlers struct {
	sync.Mutex
	load          func(bool) any
	action        func(string)
	authenticated bool
	busy          bool
}

func ConfigureApps(load func(bool) any, action func(string)) {
	appsHandlers.Lock()
	appsHandlers.load, appsHandlers.action = load, action
	appsHandlers.Unlock()
}
func ReloadApps(check bool) {
	value := C.int(0)
	if check {
		value = 1
	}
	ipa_go_apps_load(value)
}

//export ipa_go_apps_load
func ipa_go_apps_load(check C.int) {
	appsHandlers.Lock()
	load := appsHandlers.load
	appsHandlers.Unlock()
	if load == nil {
		return
	}
	go func() {
		// Serialize reloads so an older offline snapshot cannot replace a check.
		appsLoadMu.Lock()
		defer appsLoadMu.Unlock()
		raw, err := json.Marshal(load(check != 0))
		if err != nil {
			return
		}
		value := C.CString(string(raw))
		defer C.free(unsafe.Pointer(value))
		C.ipa_ios_apps_update(value)
	}()
}

//export ipa_go_apps_action
func ipa_go_apps_action(id *C.char) {
	value := C.GoString(id)
	appsHandlers.Lock()
	action := appsHandlers.action
	if !appsHandlers.authenticated {
		action = nil
	}
	appsHandlers.Unlock()
	if action != nil {
		go action(value)
	}
}

// SetAuthenticated enables installation and refresh actions. The read-only
// app list remains available while signed out or validating saved credentials.
func SetAuthenticated(authenticated bool) {
	appsHandlers.Lock()
	if appsHandlers.authenticated == authenticated {
		appsHandlers.Unlock()
		return
	}
	appsHandlers.authenticated = authenticated
	appsHandlers.Unlock()
	var value C.int
	if authenticated {
		value = 1
	}
	C.ipa_ios_apps_authenticated(value)
}

func SetAppsBusy(busy bool) {
	appsHandlers.Lock()
	if appsHandlers.busy == busy {
		appsHandlers.Unlock()
		return
	}
	appsHandlers.busy = busy
	appsHandlers.Unlock()
	var value C.int
	if busy {
		value = 1
	}
	C.ipa_ios_apps_busy(value)
}
