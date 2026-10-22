//go:build windows

package platform

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func recoveryPreflightEngine(t *testing.T) (*engine, string) {
	t.Helper()
	config := t.TempDir()
	e := newControllerTestEngine(context.Background(), t.TempDir())
	e.host = &windowsHost{}
	e.configDir = func() (string, error) { return config, nil }
	return e, config
}

func TestWindowsRecoveryPreflightReleasesAndRechecksLock(t *testing.T) {
	e, _ := recoveryPreflightEngine(t)
	device := Device{UDID: "synthetic-owned-phone", Transport: "USB"}
	for _, transport := range []string{"USB", "WiFi"} {
		device.Transport = transport
		err := e.checkInstallDevice(device)
		if err != nil {
			t.Fatal("safe Windows recovery preflight failed", err)
		}
		_, release, err := e.openStagingRegistry(device)
		if err != nil {
			t.Fatal("preflight left recovery lock held", err)
		}
		if err = e.checkInstallDevice(device); err == nil {
			release()
			t.Fatal("busy device passed provisioning preflight")
		}
		release()
		if err = e.checkInstallDevice(device); err != nil {
			t.Fatal("released recovery lock remained busy", err)
		}
	}
}

func TestWindowsRecoveryPreflightRejectsUnsafeStorage(t *testing.T) {
	e, config := recoveryPreflightEngine(t)
	parent := filepath.Join(config, "ipa-loader")
	if err := os.MkdirAll(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "device-staging"), []byte("conflicting file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.checkInstallDevice(Device{UDID: "synthetic-owned-phone", Transport: "USB"}); err == nil {
		t.Fatal("unsafe recovery path passed provisioning preflight")
	}
}

func TestWindowsRecoveryPreflightValidatesBeforeStorage(t *testing.T) {
	for _, kind := range []string{"cancelled", "missing udid", "wrong route"} {
		t.Run(kind, func(t *testing.T) {
			e, config := recoveryPreflightEngine(t)
			device := Device{UDID: "synthetic-owned-phone", Transport: "USB"}
			switch kind {
			case "cancelled":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				e.ctx = ctx
			case "missing udid":
				device.UDID = ""
			case "wrong route":
				device.Transport = "Unknown"
			}
			if err := e.checkInstallDevice(device); err == nil {
				t.Fatal("invalid or cancelled recovery preflight accepted")
			}
			if _, err := os.Stat(filepath.Join(config, "ipa-loader")); !os.IsNotExist(err) {
				t.Fatal("invalid preflight accessed recovery storage")
			}
		})
	}
}
