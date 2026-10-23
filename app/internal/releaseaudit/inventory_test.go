package releaseaudit

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestBuiltWindowsDesktop(t *testing.T) {
	path := os.Getenv("IPA_LOADER_TEST_WINDOWS_EXE")
	if path == "" {
		t.Skip("set IPA_LOADER_TEST_WINDOWS_EXE to audit a built desktop executable")
	}
	image, err := pe.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	if err := inspectDesktop(image); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopSubsystemAndIcon(t *testing.T) {
	for _, tc := range []struct {
		name      string
		subsystem uint16
		icons     []uint32
		wantOK    bool
	}{
		{"GUI with icon", pe.IMAGE_SUBSYSTEM_WINDOWS_GUI, []uint32{3, 14}, true},
		{"console with icon", pe.IMAGE_SUBSYSTEM_WINDOWS_CUI, []uint32{3, 14}, false},
		{"missing resources", pe.IMAGE_SUBSYSTEM_WINDOWS_GUI, nil, false},
		{"icon without group", pe.IMAGE_SUBSYSTEM_WINDOWS_GUI, []uint32{3}, false},
		{"group without icon", pe.IMAGE_SUBSYSTEM_WINDOWS_GUI, []uint32{14}, false},
		{"unrelated resource", pe.IMAGE_SUBSYSTEM_WINDOWS_GUI, []uint32{24}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := &pe.OptionalHeader64{Subsystem: tc.subsystem}
			image := &pe.File{OptionalHeader: header}
			if len(tc.icons) > 0 {
				data := make([]byte, 16+24*len(tc.icons))
				binary.LittleEndian.PutUint16(data[14:], uint16(len(tc.icons)))
				for i, id := range tc.icons {
					child := 16 + 8*len(tc.icons) + 16*i
					binary.LittleEndian.PutUint32(data[16+8*i:], id)
					binary.LittleEndian.PutUint32(data[20+8*i:], uint32(child)|0x80000000)
					binary.LittleEndian.PutUint16(data[child+14:], 1)
				}
				header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE] = pe.DataDirectory{VirtualAddress: 0x1000, Size: uint32(len(data))}
				image.Sections = []*pe.Section{{SectionHeader: pe.SectionHeader{VirtualAddress: 0x1000, Size: uint32(len(data))}, ReaderAt: bytes.NewReader(data)}}
			}
			if err := inspectDesktop(image); (err == nil) != tc.wantOK {
				t.Fatalf("inspectDesktop() = %v, want success %v", err, tc.wantOK)
			}
		})
	}
}

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
