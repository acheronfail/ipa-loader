package platform

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"testing"
)

// A standard Windows account needs Developer Mode or the symlink privilege.
// Skip only that capability check; other filesystem tests still run.
func testSymlink(t *testing.T, target, link string) {
	t.Helper()
	err := os.Symlink(target, link)
	if runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(1314)) {
		t.Skip("Windows symlink creation requires Developer Mode or SeCreateSymbolicLinkPrivilege")
	}
	if err != nil {
		t.Fatal(err)
	}
}

func testPrivateTempDir(t *testing.T) string {
	t.Helper()
	dir, err := privateTempDir(t.TempDir(), "private-")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
