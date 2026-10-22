//go:build linux

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

const sharingRuntimeDir = "sharing-linux"
const sharingRecipe = "build-sharing-linux.py"

var hostDevices = mobiledevice.LinuxDevices
var hostLocked = mobiledevice.LinuxLocked
var hostInstalledApps = mobiledevice.LinuxInstalledApps

func newLinuxEngine(ctx context.Context, work, team string) *engine {
	e := newEngine(ctx, work)
	runtimeRoot, runtimeErr := runtimebundle.Root()
	root, rootErr := os.UserConfigDir()
	runtimeRootDir := runtimeRoot
	if configured := os.Getenv("IPA_LOADER_LINUX_RUNTIME"); !runtimebundle.Embedded() && filepath.IsAbs(configured) {
		runtimeRootDir = configured
		runtimeErr = nil
	}
	h := &desktopHost{team: team, runtimeErr: runtimeErr, runtimeRoot: runtimeRootDir, vault: signing.IdentityVault{Dir: filepath.Join(root, "ipa-loader", "signing")}}
	e.host = h
	e.configDir = func() (string, error) {
		if rootErr != nil || !filepath.IsAbs(root) {
			return "", failure("Could not locate private Linux recovery storage")
		}
		return root, nil
	}

	return e
}

func (h *desktopHost) checkTools(e *engine) error {
	if h.runtimeErr != nil {
		return fmt.Errorf("prepare embedded runtime: %w", h.runtimeErr)
	}
	if err := e.ctx.Err(); err != nil {
		return err
	}
	if h.team != "" {
		if _, err := e.configDir(); err != nil {
			return err
		}
	}
	return e.ctx.Err()
}
