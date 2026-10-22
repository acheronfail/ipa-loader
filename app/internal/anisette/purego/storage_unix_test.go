//go:build darwin || linux

package purego

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStateStorageRejectsUnsafeFilesAndContendedLock(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private")
	if err := ensureStateDir(root); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "state")
	if err := os.WriteFile(path, []byte("synthetic"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readState(path); err == nil {
		t.Fatal("accepted broad permissions")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := readState(alias); err == nil {
		t.Fatal("accepted symlink")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := readState(path); err == nil {
		t.Fatal("accepted hardlink")
	}
	release, err := lockState(filepath.Join(root, "lock"))
	if err != nil {
		t.Fatal(err)
	}
	if second, err := lockState(filepath.Join(root, "lock")); err == nil {
		second()
		t.Fatal("concurrent provisioning allowed")
	}
	release()
	again, err := lockState(filepath.Join(root, "lock"))
	if err != nil {
		t.Fatal(err)
	}
	again()
}
