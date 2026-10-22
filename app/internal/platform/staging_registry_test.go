package platform

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testRegistry(t *testing.T) *stagingRegistry {
	t.Helper()
	e := newControllerTestEngine(context.Background(), t.TempDir())
	config, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e.configDir = func() (string, error) { return config, nil }
	r, unlock, err := e.openStagingRegistry(Device{UDID: "owned-phone"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(unlock)
	return r
}
func TestRecoveryRequiresLaterConfirmedSameAppAndDevice(t *testing.T) {
	for _, kind := range []string{"incomplete", "terminal", "uncertain", "confirmed later", "other device", "other app", "future record", "wrong path", "malformed", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			r := testRegistry(t)
			current := freshStagingRecord("PublicStaging/IPALoader-"+strings.Repeat("a", 32), appInfo{BundleID: "org.example.owned", Build: "9"}, Device{UDID: "owned-phone"})
			previous := freshStagingRecord("PublicStaging/IPALoader-"+strings.Repeat("b", 32), appInfo{BundleID: "org.example.owned", Build: "8"}, Device{UDID: "owned-phone"})
			previous.Created = current.Created.Add(-time.Minute)
			previous.MayHaveSubmitted = true
			switch kind {
			case "incomplete":
				previous.MayHaveSubmitted = false
			case "terminal":
				previous.Terminal = true
			case "other device":
				previous.UDID = "other-phone"
			case "other app":
				previous.BundleID = "org.example.other"
			case "future record":
				previous.Created = current.Created.Add(time.Minute)
			}
			if err := r.save(previous); err != nil {
				t.Fatal(err)
			}
			path := r.path(previous)
			if kind == "wrong path" {
				previous.Package = "PublicStaging/personal.ipa"
				b, _ := json.Marshal(previous)
				if err := os.WriteFile(path, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "malformed" {
				if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "symlink" {
				target := filepath.Join(t.TempDir(), "unrelated.json")
				body, _ := os.ReadFile(path)
				if err := os.WriteFile(target, body, 0600); err != nil {
					t.Fatal(err)
				}
				os.Remove(path)
				testSymlink(t, target, path)
			}
			fake := &stagedFake{}
			cleaned := r.recover(context.Background(), fake, current, kind == "confirmed later")
			want := kind == "incomplete" || kind == "terminal" || kind == "confirmed later"
			if (cleaned == 1) != want || (fake.removed == 2) != want {
				t.Fatal("cleanup crossed confirmation, identity, time or path boundary")
			}
			if _, err := os.Lstat(path); os.IsNotExist(err) != want {
				t.Fatal("recovery record was removed incorrectly")
			}
		})
	}
}
func TestStagingLockSerializesAndReleases(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "device.lock")
	unlock, err := lockStaging(path)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := lockStaging(path); err == nil {
		second()
		t.Fatal("concurrent device install acquired lock")
	}
	unlock()
	release, err := lockStaging(path)
	if err != nil {
		t.Fatal("released lock not reusable")
	}
	release()
}
