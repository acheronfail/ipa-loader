package platform

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"howett.net/plist"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnsupportedCapabilitiesAreNamed(t *testing.T) {
	err := basicEntitlements(map[string]any{
		"com.example.unsupported.z": true,
		"com.example.unsupported.a": true,
	})
	if err == nil || !strings.HasSuffix(err.Error(), "com.example.unsupported.a, com.example.unsupported.z") {
		t.Fatalf("unsupported capabilities were not identified in stable order: %v", err)
	}
}

func thin() []byte {
	b := make([]byte, 56)
	binary.LittleEndian.PutUint32(b, 0xfeedfacf)
	binary.LittleEndian.PutUint32(b[4:], 0x100000c)
	binary.LittleEndian.PutUint32(b[12:], 2)
	binary.LittleEndian.PutUint32(b[16:], 1)
	binary.LittleEndian.PutUint32(b[20:], 24)
	binary.LittleEndian.PutUint32(b[32:], 0x32)
	binary.LittleEndian.PutUint32(b[36:], 24)
	binary.LittleEndian.PutUint32(b[40:], 2)
	return b
}

type zipMember struct {
	name string
	data []byte
	mode os.FileMode
}

func writeIPA(t *testing.T, members []zipMember) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "input.ipa")
	f, e := os.Create(p)
	if e != nil {
		t.Fatal(e)
	}
	z := zip.NewWriter(f)
	for _, m := range members {
		h := &zip.FileHeader{Name: m.name, Method: zip.Deflate}
		if m.mode != 0 {
			h.SetMode(m.mode)
		}
		w, e := z.CreateHeader(h)
		if e != nil {
			t.Fatal(e)
		}
		_, _ = w.Write(m.data)
	}
	if e = z.Close(); e != nil {
		t.Fatal(e)
	}
	f.Close()
	return p
}
func members(t *testing.T) []zipMember {
	info, e := plist.Marshal(map[string]any{"CFBundleIdentifier": "org.example.fixture", "CFBundleExecutable": "Fixture", "CFBundleShortVersionString": "1.0", "CFBundleVersion": "1"}, plist.XMLFormat)
	if e != nil {
		t.Fatal(e)
	}
	return []zipMember{{"Payload/Fixture.app/Info.plist", info, 0}, {"Payload/Fixture.app/Fixture", thin(), 0}, {"Payload/Fixture.app/resource.txt", []byte("owned fixture"), 0}}
}
func TestExtractPlainIPA(t *testing.T) {
	a, e := extractIPA(context.Background(), writeIPA(t, members(t)), t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if a.BundleID != "org.example.fixture" || a.Build != "1" {
		t.Fatal("metadata mismatch")
	}
}

func TestResolvedIdentityChangesOnlyExtractedMetadata(t *testing.T) {
	input := writeIPA(t, members(t))
	before, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	app, err := extractIPA(context.Background(), input, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	originalInfo, err := os.ReadFile(filepath.Join(app.Path, "Info.plist"))
	if err != nil {
		t.Fatal(err)
	}
	ids, err := standardBundleIdentity(app.BundleID, "TEAM")
	if err != nil {
		t.Fatal(err)
	}
	ids.Installed = ids.Original
	if err = app.applyBundleIdentity(ids); err != nil {
		t.Fatal(err)
	}
	unchanged, _ := os.ReadFile(filepath.Join(app.Path, "Info.plist"))
	if !bytes.Equal(originalInfo, unchanged) {
		t.Fatal("unchanged paid metadata was rewritten")
	}
	ids.Installed = ids.Registration
	if err = app.applyBundleIdentity(ids); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(app.Path, "Info.plist"))
	metadata, err := dictionary(data)
	if err != nil || metadata["CFBundleIdentifier"] != ids.Registration || metadata["ALTBundleIdentifier"] != ids.Original || app.BundleID != ids.Registration || metadata["CFBundleExecutable"] != "Fixture" || metadata["CFBundleVersion"] != "1" {
		t.Fatal("free-account metadata mismatch")
	}
	ids.Installed = ids.Original
	if err = app.applyBundleIdentity(ids); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(filepath.Join(app.Path, "Info.plist"))
	metadata, _ = dictionary(data)
	if _, present := metadata["ALTBundleIdentifier"]; present {
		t.Fatal("paid metadata retained ALT override")
	}
	after, err := os.ReadFile(input)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("source IPA changed")
	}
}

func TestUnsafeArchiveAndNestedCodeReject(t *testing.T) {
	cases := []zipMember{{"../outside", nil, 0}, {"Payload/Fixture.app/INFO.plist", nil, 0}, {"Payload/Fixture.app/link", nil, os.ModeSymlink | 0777}, {"Payload/Fixture.app/PlugIns/Evil.appex/Info.plist", []byte("x"), 0}, {"Payload/Fixture.app/library.dylib", thin(), 0}, {"Payload/Fixture.app/file/child", nil, 0}}
	for _, bad := range cases {
		t.Run(bad.name, func(t *testing.T) {
			m := append(members(t), bad)
			if bad.name == "Payload/Fixture.app/file/child" {
				m = append(m, zipMember{"Payload/Fixture.app/file", []byte("x"), 0})
			}
			if _, e := extractIPA(context.Background(), writeIPA(t, m), t.TempDir()); e == nil {
				t.Fatal("unsafe input accepted")
			}
		})
	}
}
func TestMachOEncryptedAndWrongPlatformReject(t *testing.T) {
	wrong := thin()
	binary.LittleEndian.PutUint32(wrong[40:], 7)
	if validateMachO(wrong) == nil {
		t.Fatal("simulator accepted")
	}
	encrypted := append(thin(), make([]byte, 24)...)
	binary.LittleEndian.PutUint32(encrypted[16:], 2)
	binary.LittleEndian.PutUint32(encrypted[20:], 48)
	binary.LittleEndian.PutUint32(encrypted[56:], 0x2c)
	binary.LittleEndian.PutUint32(encrypted[60:], 24)
	binary.LittleEndian.PutUint32(encrypted[72:], 1)
	if validateMachO(encrypted) == nil {
		t.Fatal("encrypted accepted")
	}
	for i := 0; i < len(thin()); i++ {
		if validateMachO(thin()[:i]) == nil {
			t.Fatalf("truncated executable accepted %d", i)
		}
	}
}
func blob(magic uint32, payload []byte) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b, magic)
	binary.BigEndian.PutUint32(b[4:], uint32(len(payload)+8))
	return append(b, payload...)
}
func super(slots []uint32, blobs [][]byte) []byte {
	b := make([]byte, 12+8*len(slots))
	binary.BigEndian.PutUint32(b, 0xfade0cc0)
	binary.BigEndian.PutUint32(b[8:], uint32(len(slots)))
	for i, s := range slots {
		binary.BigEndian.PutUint32(b[12+8*i:], s)
		binary.BigEndian.PutUint32(b[16+8*i:], uint32(len(b)))
		b = append(b, blobs[i]...)
	}
	binary.BigEndian.PutUint32(b[4:], uint32(len(b)))
	return b
}
func der(tag byte, data []byte) []byte {
	if len(data) >= 128 {
		panic("fixture too long")
	}
	return append([]byte{tag, byte(len(data))}, data...)
}
func TestExistingEntitlementsCannotBeDiscarded(t *testing.T) {
	basic := map[string]any{"application-identifier": "OLDTEAM.org.example.fixture", "get-task-allow": true, "keychain-access-groups": []any{"OLDTEAM.org.example.fixture"}}
	xml, _ := plist.Marshal(basic, plist.XMLFormat)
	if e := validateSignature(super([]uint32{5}, [][]byte{blob(0xfade7171, xml)})); e != nil {
		t.Fatal(e)
	}
	basic["com.example.unsupported-capability"] = true
	xml, _ = plist.Marshal(basic, plist.XMLFormat)
	if validateSignature(super([]uint32{5}, [][]byte{blob(0xfade7171, xml)})) == nil {
		t.Fatal("capability silently discarded")
	}
	xml, _ = plist.Marshal(map[string]any{"get-task-allow": true}, plist.XMLFormat)
	entry := der(0x30, append(der(12, []byte("get-task-allow")), der(1, []byte{0})...))
	d := der(0x70, append(der(2, []byte{1}), der(0xb0, entry)...))
	if validateSignature(super([]uint32{5, 7}, [][]byte{blob(0xfade7171, xml), blob(0xfade7172, d)})) == nil {
		t.Fatal("different XML and DER accepted")
	}
	if validateSignature(super([]uint32{5, 5}, [][]byte{blob(0xfade7171, xml), blob(0xfade7171, xml)})) == nil {
		t.Fatal("duplicate slot accepted")
	}
	if _, e := derEntitlements(bytes.Repeat([]byte{0x70, 0x80}, 10)); e == nil {
		t.Fatal("indefinite DER accepted")
	}
}
func TestCancelledPreflightDoesNotExtract(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	work := t.TempDir()
	if _, e := extractIPA(ctx, writeIPA(t, members(t)), work); e == nil {
		t.Fatal("cancellation ignored")
	}
	entries, _ := os.ReadDir(work)
	if len(entries) != 0 {
		t.Fatal("cancelled extraction wrote files")
	}
}
func TestLocalizedResourcesAndUnicodeCollision(t *testing.T) {
	m := append(members(t), zipMember{"Payload/Fixture.app/日本語.lproj/café.txt", []byte("localized content"), 0})
	if _, e := extractIPA(context.Background(), writeIPA(t, m), t.TempDir()); e != nil {
		t.Fatal("ordinary Unicode resource rejected", e)
	}
	m = append(m, zipMember{"Payload/Fixture.app/日本語.lproj/cafe\u0301.txt", []byte("collision"), 0})
	if _, e := extractIPA(context.Background(), writeIPA(t, m), t.TempDir()); e == nil {
		t.Fatal("Unicode normalization collision accepted")
	}
	m = append(members(t), zipMember{"Payload/Fixture.app/straße.txt", nil, 0}, zipMember{"Payload/Fixture.app/STRASSE.txt", nil, 0})
	if _, e := extractIPA(context.Background(), writeIPA(t, m), t.TempDir()); e == nil {
		t.Fatal("Unicode case-fold collision accepted")
	}
}
