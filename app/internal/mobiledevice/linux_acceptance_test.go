//go:build linux

package mobiledevice

import (
	"os"
	"testing"
)

// Live checks are opt-in and require an explicitly named device. The transfer
// check writes and cleans only a new task-owned synthetic staging namespace;
// neither check submits installation or changes apps on the phone.
func TestLinuxSelectedReadOnly(t *testing.T) {
	if os.Getenv("IPA_LOADER_TEST_LINUX_DEVICE") != "1" {
		t.Skip("explicit selected Linux iPhone identity/inventory check")
	}
	checkSelectedReadOnly(t)
}

func TestLinuxSelectedOwnedAFCTransfer(t *testing.T) {
	if os.Getenv("IPA_LOADER_TEST_LINUX_AFC") != "1" {
		t.Skip("explicit owned synthetic Linux staging transfer, no installation")
	}
	checkSelectedOwnedAFCTransfer(t)
}
