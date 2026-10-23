//go:build darwin && !ios

package platform

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestNativeLocalGroupFallback(t *testing.T) {
	if _, err := exec.LookPath("xcrun"); err != nil {
		t.Skip("Xcode command line tools required")
	}
	work := t.TempDir()
	binary := filepath.Join(work, "local-groups-test")
	if out, err := exec.Command("xcrun", "--sdk", "macosx", "clang", "-fobjc-arc", "-framework", "Foundation", "-framework", "Security", "testdata/local_groups.m", "compat/fishhook.c", "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile fallback harness: %v\n%s", err, out)
	}
	if out, err := exec.Command(binary, work).CombinedOutput(); err != nil {
		t.Fatalf("local-group fallback: %v\n%s", err, out)
	}
}
