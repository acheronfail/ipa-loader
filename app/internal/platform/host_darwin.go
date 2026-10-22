//go:build darwin && !ios

package platform

import (
	"context"
	"ipa-loader/app/internal/mobiledevice"
	"ipa-loader/app/internal/signing"
	"os"
	"path/filepath"
)

const sharingRuntimeDir = "sharing-macos"
const sharingRecipe = "build-sharing-macos.go"

var hostDevices = mobiledevice.DarwinDevices
var hostLocked = mobiledevice.DarwinLocked
var hostInstalledApps = mobiledevice.DarwinInstalledApps

func newDarwinEngine(ctx context.Context, work, team string) *engine {
	e := newEngine(ctx, work)
	root, err := os.UserConfigDir()
	h := &desktopHost{team: team, vault: signing.IdentityVault{Dir: filepath.Join(root, "ipa-loader", "signing")}}
	if executable, execErr := os.Executable(); execErr == nil && filepath.Base(filepath.Dir(executable)) == "MacOS" && filepath.Base(filepath.Dir(filepath.Dir(executable))) == "Contents" {
		h.runtimeRoot = filepath.Join(filepath.Dir(filepath.Dir(executable)), "Resources")
	}
	e.host = &darwinHost{desktopHost: h}
	e.configDir = func() (string, error) {
		if err != nil || !filepath.IsAbs(root) {
			return "", failure("Could not locate private macOS recovery storage")
		}
		return root, nil
	}
	return e
}

type darwinHost struct{ *desktopHost }

// Device discovery, lockdown, inventory and installation all use the system
// usbmuxd service through Go. No developer tools are required at runtime.
func (h *darwinHost) checkTools(e *engine) error {
	if _, err := e.configDir(); err != nil {
		return err
	}
	return e.ctx.Err()
}

func (h *darwinHost) sharingLibrary(e *engine) (string, error) {
	if h.runtimeRoot != "" {
		return e.copyWindowsSharingLibrary(filepath.Join(h.runtimeRoot, sharingRuntimeDir))
	}
	// Source development runs can build with the local SDK. Releases carry the
	// adapter and provenance, and never fall back to runtime compilation.
	return e.buildDarwinSharingLibrary()
}
