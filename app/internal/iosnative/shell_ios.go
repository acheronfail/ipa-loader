//go:build ios

package iosnative

/*
#include <stdlib.h>
void ipa_ios_run(void);
char *ipa_ios_confirm_import(const char *json);
void ipa_ios_shell_update(const char *json);
char *ipa_ios_prompt(const char *title,const char *message,const char *initial,int secure,int code,int confirm);
*/
import "C"
import (
	"encoding/json"
	"errors"
	"ipa-loader/app/internal/ipa"
	"os"
	"runtime"
	"sync"
	"unsafe"
)

func init() { runtime.LockOSThread() }

var shellHandlers struct {
	sync.Mutex
	start  func()
	action func([]byte)
}

// Run enters UIKit on Go's original main thread. Signing/network work is always
// dispatched to Go workers; UIKit presentation remains on the main queue.
func Run(start func(), action func([]byte)) {
	shellHandlers.Lock()
	shellHandlers.start = start
	shellHandlers.action = action
	shellHandlers.Unlock()
	C.ipa_ios_run()
}

//export ipa_go_shell_started
func ipa_go_shell_started() {
	shellHandlers.Lock()
	start := shellHandlers.start
	shellHandlers.Unlock()
	if start != nil {
		go start()
	}
}

//export ipa_go_shell_action
func ipa_go_shell_action(raw *C.char) {
	data := []byte(C.GoString(raw))
	shellHandlers.Lock()
	action := shellHandlers.action
	shellHandlers.Unlock()
	if action != nil {
		go action(data)
	}
}
func UpdateShell(state any) {
	raw, err := json.Marshal(state)
	if err != nil {
		return
	}
	value := C.CString(string(raw))
	defer C.free(unsafe.Pointer(value))
	C.ipa_ios_shell_update(value)
}

// Prompt is a native confirmation or credential dialog, called from a worker.
// Text never enters a snapshot, an activity log, or persistent preferences.
func Prompt(title, message, initial string, secure, code, confirm bool) (string, error) {
	t, m, i := C.CString(title), C.CString(message), C.CString(initial)
	defer C.free(unsafe.Pointer(t))
	defer C.free(unsafe.Pointer(m))
	defer C.free(unsafe.Pointer(i))
	flag := func(b bool) C.int {
		if b {
			return 1
		}
		return 0
	}
	p := C.ipa_ios_prompt(t, m, i, flag(secure), flag(code), flag(confirm))
	if p == nil {
		return "", errors.New("Cancelled")
	}
	defer C.free(unsafe.Pointer(p))
	return C.GoString(p), nil
}

func ConfirmImport(info *ipa.Info) (bool, bool, error) {
	var size int64
	if stat, err := os.Stat(info.Path); err == nil {
		size = stat.Size()
	}
	raw, err := json.Marshal(struct {
		*ipa.Info
		Size int64
	}{info, size})
	if err != nil {
		return false, false, err
	}
	value := C.CString(string(raw))
	defer C.free(unsafe.Pointer(value))
	response := C.ipa_ios_confirm_import(value)
	if response == nil {
		return false, false, nil
	}
	defer C.free(unsafe.Pointer(response))
	var decision struct {
		Accepted, KeepIPA bool
		Selection         *ipa.ExtensionSelection
	}
	if err := json.Unmarshal([]byte(C.GoString(response)), &decision); err != nil {
		return false, false, err
	}
	if decision.Accepted {
		info.Selection = decision.Selection
	}
	return decision.Accepted, decision.KeepIPA, nil
}
