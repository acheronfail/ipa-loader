package platform

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRefreshGraphDoesNotSkipProvisionedBundles(t *testing.T) {
	for _, tc := range []struct {
		name, path  string
		unsupported bool
	}{
		{"main", "embedded.mobileprovision", false},
		{"direct extension", "PlugIns/Widget.appex/embedded.mobileprovision", false},
		{"nested extension", "PlugIns/Widget.appex/PlugIns/Child.appex/embedded.mobileprovision", true},
		{"watch app", "Watch/Companion.app/embedded.mobileprovision", true},
		{"misplaced extension", "Resources/Widget.appex/embedded.mobileprovision", true},
		{"other provisioning", "Frameworks/Kit.framework/embedded.mobileprovision", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "Fixture.app")
			path := filepath.Join(root, filepath.FromSlash(tc.path))
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("profile"), 0600); err != nil {
				t.Fatal(err)
			}
			paths, err := refreshMemberPaths(root)
			if errors.Is(err, errProfileRefreshUnsupported) != tc.unsupported {
				t.Fatalf("graph %v error %v", paths, err)
			}
			if !tc.unsupported && (err != nil || len(paths) == 0 || paths[0] != root) {
				t.Fatalf("graph %v error %v", paths, err)
			}
		})
	}
}
