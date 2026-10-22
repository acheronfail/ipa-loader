//go:build darwin && cgo && !ios

package ui

/*
#cgo CFLAGS: -fobjc-arc
#cgo LDFLAGS: -framework AppKit -framework UniformTypeIdentifiers
#include <stdlib.h>
#include <stdint.h>
char *ipa_choose_file(const char *current, uintptr_t parent, int *failed);
*/
import "C"

import (
	"errors"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver"
	"unsafe"
)

func nativeIPAFile(window fyne.Window, current string) (string, error) {
	path := C.CString(current)
	defer C.free(unsafe.Pointer(path))
	var failed C.int
	var parent uintptr
	if native, ok := window.(driver.NativeWindow); ok {
		native.RunNative(func(ctx any) {
			if mac, ok := ctx.(driver.MacWindowContext); ok {
				parent = mac.NSWindow
			}
		})
	}
	if parent == 0 {
		return "", errors.New("The system file picker could not find its parent window")
	}
	selected := C.ipa_choose_file(path, C.uintptr_t(parent), &failed)
	if selected != nil {
		defer C.free(unsafe.Pointer(selected))
	}
	if failed != 0 {
		return "", errors.New("The system file picker could not be opened. You can also drag an IPA into this window")
	}
	if selected == nil {
		return "", nil
	}
	return C.GoString(selected), nil
}
