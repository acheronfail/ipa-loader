//go:build windows

package platform

import (
	"context"
	"os"
	"path/filepath"
)

// ValidateWindowsRuntime checks a release using the same sharing-adapter hashes,
// source inventory and sharing-adapter checks as a real installation. It never
// opens an account, contacts Apple, pairs a device or creates signing material.
func ValidateWindowsRuntime(ctx context.Context, root string) error {
	if !filepath.IsAbs(root) {
		return failure("Select an absolute Windows package directory")
	}
	work, err := privateTempDir("", "ipa-loader-package-check-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	e := newEngine(ctx, work)
	h := &windowsHost{runtimeRoot: root}
	if err = h.checkTools(e); err != nil {
		return err
	}
	_, err = e.copyWindowsSharingLibrary(filepath.Join(root, "sharing-windows"))
	return err
}
