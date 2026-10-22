//go:build darwin && !ios

package platform

import (
	"context"
	"os"
	"path/filepath"
)

// ValidateDarwinRuntime checks packaged sharing bytes and provenance without
// contacting Apple, opening Keychain, or connecting to a device.
func ValidateDarwinRuntime(ctx context.Context, resources string) error {
	if !filepath.IsAbs(resources) {
		return failure("Select an absolute macOS Resources directory")
	}
	work, err := privateTempDir("", "ipa-loader-macos-check-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	e := newEngine(ctx, work)
	_, err = e.copyWindowsSharingLibrary(filepath.Join(resources, sharingRuntimeDir))
	return err
}
