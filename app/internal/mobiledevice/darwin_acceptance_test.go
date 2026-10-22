//go:build darwin

package mobiledevice

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestDarwinDiscovery(t *testing.T) {
	if os.Getenv("IPA_LOADER_TEST_MACOS_DEVICE") != "1" {
		t.Skip("explicit macOS discovery")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	devices, err := DarwinDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range devices {
		t.Logf("Device: %s (%s), iOS %s", d.Name, d.Transport, d.OSVersion)
	}
}
func TestDarwinSelectedReadOnly(t *testing.T) {
	if os.Getenv("IPA_LOADER_TEST_MACOS_DEVICE") != "1" {
		t.Skip("explicit selected macOS identity/inventory")
	}
	checkSelectedReadOnly(t)
}
func TestDarwinSelectedOwnedAFCTransfer(t *testing.T) {
	if os.Getenv("IPA_LOADER_TEST_MACOS_AFC") != "1" {
		t.Skip("explicit synthetic macOS staging, no installation")
	}
	checkSelectedOwnedAFCTransfer(t)
}
