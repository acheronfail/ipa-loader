package platform

import (
	"context"
	"encoding/binary"
	"howett.net/plist"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func library() []byte {
	b := thin()
	binary.LittleEndian.PutUint32(b[12:], 6)
	return b
}
func frameworkMembers(t *testing.T, prefix string) []zipMember {
	t.Helper()
	info, err := plist.Marshal(map[string]any{"CFBundleExecutable": "Kit", "CFBundleIdentifier": "org.example.Kit", "CFBundlePackageType": "FMWK"}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	return []zipMember{{prefix + "/Info.plist", info, 0}, {prefix + "/Kit", library(), 0}, {prefix + "/proof.txt", []byte("resource"), 0}}
}

func TestEmbeddedGraphAndContainmentOrder(t *testing.T) {
	m := append(members(t), frameworkMembers(t, "Payload/Fixture.app/Frameworks/Kit.framework")...)
	m = append(m, frameworkMembers(t, "Payload/Fixture.app/Frameworks/Kit.framework/Frameworks/Child.framework")...)
	m = append(m, zipMember{"Payload/Fixture.app/Frameworks/libMath.dylib", library(), 0})
	app, err := extractIPA(context.Background(), writeIPA(t, m), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, object := range app.Embedded {
		p, _ := filepath.Rel(app.Path, object.Path)
		paths = append(paths, filepath.ToSlash(p))
	}
	want := []string{"Frameworks/Kit.framework/Frameworks/Child.framework", "Frameworks/Kit.framework", "Frameworks/libMath.dylib"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("wrong signing graph: %v", paths)
	}
}

func TestEmbeddedCodeRejectsInvalidMembers(t *testing.T) {
	for _, kind := range []string{"framework metadata", "missing executable", "simulator", "missing platform", "executable disguised as dylib", "encrypted dylib", "fat dylib", "hidden executable", "misplaced framework", "symlink", "extension"} {
		t.Run(kind, func(t *testing.T) {
			m := append(members(t), frameworkMembers(t, "Payload/Fixture.app/Frameworks/Kit.framework")...)
			lib := library()
			switch kind {
			case "framework metadata":
				m[3].data = []byte("invalid plist")
			case "missing executable":
				m = append(m[:4], m[5:]...)
			case "simulator":
				binary.LittleEndian.PutUint32(lib[40:], 7)
			case "missing platform":
				binary.LittleEndian.PutUint32(lib[32:], 0x1b)
			case "executable disguised as dylib":
				lib = thin()
			case "encrypted dylib":
				lib = append(lib, make([]byte, 24)...)
				binary.LittleEndian.PutUint32(lib[16:], 2)
				binary.LittleEndian.PutUint32(lib[20:], 48)
				binary.LittleEndian.PutUint32(lib[56:], 0x2c)
				binary.LittleEndian.PutUint32(lib[60:], 24)
				binary.LittleEndian.PutUint32(lib[72:], 1)
			case "fat dylib":
				binary.LittleEndian.PutUint32(lib, 0xbebafeca)
			case "hidden executable":
				m = append(m, zipMember{"Payload/Fixture.app/Resources/hidden", library(), 0})
			case "misplaced framework":
				for i := 3; i < len(m); i++ {
					m[i].name = strings.Replace(m[i].name, "/Frameworks/", "/Resources/", 1)
				}
			case "symlink":
				m = append(m, zipMember{"Payload/Fixture.app/Frameworks/link", []byte("/tmp/outside"), os.ModeSymlink | 0777})
			case "extension":
				m = append(m, zipMember{"Payload/Fixture.app/PlugIns/Test.appex/Info.plist", []byte("x"), 0})
			}
			m = append(m, zipMember{"Payload/Fixture.app/Frameworks/libMath.dylib", lib, 0})
			if _, err := extractIPA(context.Background(), writeIPA(t, m), t.TempDir()); err == nil {
				t.Fatal("unsupported embedded input accepted")
			}
		})
	}
}

func TestLegacyIPhoneLibraryPlatform(t *testing.T) {
	b := library()
	binary.LittleEndian.PutUint32(b[32:], 0x25)
	if err := validateMachOType(b, 6); err != nil {
		t.Fatal(err)
	}
}
