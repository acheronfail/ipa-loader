package releaseaudit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSystemLibraryPolicy(t *testing.T) {
	for _, name := range []string{"KERNEL32.dll", "api-ms-win-crt-runtime-l1-1-0.dll", "OPENGL32.dll"} {
		if !systemLibrary(name) {
			t.Fatal("Windows system dependency rejected")
		}
	}
	for _, name := range []string{"libcrypto-3-x64.dll", "vcruntime140.dll", "../kernel32.dll", "C:\\Windows\\kernel32.dll", "kernel32.dll:extra", "kernel32.exe"} {
		if systemLibrary(name) {
			t.Fatal("non-system dependency accepted")
		}
	}
}

func TestInventoryExcludesManifestAndRefusesPrivateState(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "README.txt"), []byte("public package"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "release-manifest.json"), []byte("previous inventory"), 0600); err != nil {
		t.Fatal(err)
	}
	records, err := Inventory(root)
	if err != nil || len(records) != 1 || records[0].Path != "README.txt" || len(records[0].SHA256) != 64 {
		t.Fatal("invalid package inventory", err)
	}
	for _, name := range []string{".env", "sessions.dpapi", "profile.mobileprovision", "identity.p12", "ipa-loader-anisette.exe", "IPA-LOADER-ANISETTE.EXE", "openssl", "openssl.exe", "zsign", "zsign.exe"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, name)
			if err := os.WriteFile(path, []byte("synthetic private state"), 0600); err != nil {
				t.Fatal(err)
			}
			defer os.Remove(path)
			if _, err := Inventory(root); err == nil {
				t.Fatal("private state entered release")
			}
		})
	}
}
