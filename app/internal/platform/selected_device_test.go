package platform

import (
	"os"
	"testing"
)

// Live checks must explicitly select a device; no personal device is a default.
func selectedTestDeviceName(t *testing.T) string {
	t.Helper()
	name := os.Getenv("IPA_LOADER_TEST_DEVICE_NAME")
	if name == "" {
		t.Fatal("set IPA_LOADER_TEST_DEVICE_NAME for the explicit live check")
	}
	return name
}
