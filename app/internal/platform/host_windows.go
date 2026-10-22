//go:build windows

package platform

import (
	"context"
	"fmt"
	"ipa-loader/app/internal/mobiledevice"
	"ipa-loader/app/internal/runtimebundle"
	"ipa-loader/app/internal/signing"
	"os"
	"path/filepath"
)

type windowsHost = desktopHost

const sharingRuntimeDir = "sharing-windows"
const sharingRecipe = "build-sharing-windows.ps1"

var hostDevices = mobiledevice.WindowsDevices
var hostLocked = mobiledevice.WindowsLocked
var hostInstalledApps = mobiledevice.WindowsInstalledApps

func newWindowsEngine(ctx context.Context, work, team string) *engine {
	e := newEngine(ctx, work)
	runtimeRoot, runtimeErr := runtimebundle.Root()
	h := &windowsHost{team: team, runtimeErr: runtimeErr, runtimeRoot: runtimeRoot, vault: signing.IdentityVault{Dir: filepath.Join(os.Getenv("LOCALAPPDATA"), "ipa-loader", "signing")}}
	e.host = h
	e.configDir = func() (string, error) {
		root := os.Getenv("LOCALAPPDATA")
		if !filepath.IsAbs(root) {
			return "", failure("Could not locate local Windows installation recovery storage")
		}
		return root, nil
	}

	return e
}

func (h *windowsHost) checkTools(e *engine) error {
	if h.runtimeErr != nil {
		return fmt.Errorf("prepare embedded runtime: %w", h.runtimeErr)
	}
	if err := e.ctx.Err(); err != nil {
		return err
	}
	return e.ctx.Err()
}
