//go:build darwin

package platform

import (
	"context"
	"ipa-loader/app/internal/mobiledevice"
	"os"
	"path/filepath"
	"testing"
)

func TestDarwinDeviceOperationsWithoutDeveloperTools(t *testing.T) {
	e := newDarwinEngine(context.Background(), testPrivateTempDir(t), "TESTTEAM10")
	root := testPrivateTempDir(t)
	e.configDir = func() (string, error) { return root, nil }
	e.run = func(name string, args ...string) ([]byte, []byte, error) {
		t.Fatalf("unexpected subprocess: %s", name)
		return nil, nil, nil
	}
	oldDevices, oldLocked, oldApps := hostDevices, hostLocked, hostInstalledApps
	t.Cleanup(func() { hostDevices, hostLocked, hostInstalledApps = oldDevices, oldLocked, oldApps })
	hostDevices = func(context.Context) ([]mobiledevice.WindowsDevice, error) {
		return []mobiledevice.WindowsDevice{{UDID: "owned-phone", Name: "Test iPhone", Transport: "USB"}}, nil
	}
	hostLocked = func(context.Context, string) (bool, error) { return false, nil }
	hostInstalledApps = func(context.Context, string) ([]map[string]any, error) {
		return []map[string]any{{"CFBundleIdentifier": "org.example.fixture", "CFBundleVersion": "3"}}, nil
	}
	if err := e.checkDeveloperTools(); err != nil {
		t.Fatal(err)
	}
	devices, err := Devices(e.ctx)
	if err != nil || len(devices) != 1 || devices[0].ID != "owned-phone" {
		t.Fatal(devices, err)
	}
	for _, label := range []string{"device-details", "device-lock-state", "existing-app", "installed-app"} {
		if _, err := e.deviceJSON(label, "--device", "owned-phone"); err != nil {
			t.Fatal(label, err)
		}
	}
	for _, transport := range []string{"USB", "WiFi"} {
		err := e.checkInstallDevice(Device{UDID: "owned-phone", Transport: transport})
		if err != nil {
			t.Fatal(transport, err)
		}
	}
}

func TestDarwinPackagedSharingNeverCompilesAtRuntime(t *testing.T) {
	root := syntheticSharingPackage(t)
	e := newEngine(context.Background(), testPrivateTempDir(t))
	e.run = func(name string, args ...string) ([]byte, []byte, error) {
		t.Fatalf("unexpected runtime compiler: %s", name)
		return nil, nil, nil
	}
	h := &darwinHost{desktopHost: &desktopHost{runtimeRoot: root}}
	// Missing packaged bytes fail instead of invoking the SDK/compiler.
	if _, err := h.sharingLibrary(e); err == nil {
		t.Fatal("missing packaged adapter accepted")
	}
	resources := t.TempDir()
	if err := os.Rename(root, filepath.Join(resources, sharingRuntimeDir)); err != nil {
		t.Fatal(err)
	}
	h.runtimeRoot = resources
	// A valid package uses the same host path without invoking developer tools.
	if _, err := h.sharingLibrary(e); err != nil {
		t.Fatal(err)
	}
}
