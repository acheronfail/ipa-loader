//go:build !windows

package platform

import (
	"os"
	"testing"
)

func testPublicFile(t *testing.T, path string) func() {
	t.Helper()
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
