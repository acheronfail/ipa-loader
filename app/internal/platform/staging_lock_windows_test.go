//go:build windows

package platform

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestWindowsStagingLockAcrossProcesses(t *testing.T) {
	if path := os.Getenv("IPA_LOADER_TEST_LOCK_PATH"); path != "" {
		release, err := lockStaging(path)
		wantHeld := os.Getenv("IPA_LOADER_TEST_LOCK_HELD") == "1"
		if release != nil {
			release()
		}
		if (err != nil) != wantHeld {
			t.Fatal("cross-process lock state incorrect")
		}
		return
	}
	path := filepath.Join(testPrivateTempDir(t), "device.lock")
	// Create once and release so the cross-process check uses an existing file,
	// exercising LockFileEx rather than just exclusive file creation.
	release, err := lockStaging(path)
	if err != nil {
		t.Fatal(err)
	}
	release()
	release, err = lockStaging(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	check := func(held string) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestWindowsStagingLockAcrossProcesses$")
		cmd.Env = append(os.Environ(), "IPA_LOADER_TEST_LOCK_PATH="+path, "IPA_LOADER_TEST_LOCK_HELD="+held)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("lock child failed: %v: %s", err, out)
		}
	}
	check("1")
	release()
	check("0")
}

func TestWindowsDiskSpaceQuery(t *testing.T) {
	dir := t.TempDir()
	if available, err := availableDiskBytes(dir); err != nil || available == 0 {
		t.Fatal("Windows free disk space unavailable", err)
	}
	if _, err := availableDiskBytes(filepath.Join(dir, "missing", "directory")); err == nil {
		t.Fatal("missing disk-space query path accepted")
	}
}
