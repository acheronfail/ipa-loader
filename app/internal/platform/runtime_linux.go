//go:build linux

package platform

import (
	"context"
	"os"
	"path/filepath"
)

// ValidateLinuxRuntime checks the pure Go release sharing adapter
// package without contacting Apple or opening a device or credential vault.
func ValidateLinuxRuntime(ctx context.Context, root string) error {
	if !filepath.IsAbs(root) {
		return failure("Select an absolute Linux package directory")
	}
	work, err := privateTempDir("", "ipa-loader-package-check-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	e := newEngine(ctx, work)
	h := &desktopHost{runtimeRoot: root}
	if err = h.checkTools(e); err != nil {
		return err
	}
	_, err = e.copyWindowsSharingLibrary(filepath.Join(root, "sharing-linux"))
	return err
}
