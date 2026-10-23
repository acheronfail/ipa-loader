package ipa

import (
	"howett.net/plist"
	"reflect"
	"testing"
)

func TestExtensionPreviewAndAppIDCost(t *testing.T) {
	files := map[string][]byte{"Payload/Test.app/Info.plist": infoBytes(t, plist.BinaryFormat)}
	for _, tc := range []struct{ path, id, name, key, point string }{
		{"PlugIns/Share.appex", "org.example.fixture.share", "Share", "NSExtension", "NSExtensionPointIdentifier"},
		{"Extensions/Migrate.appex", "org.example.fixture.migrate", "Migrate", "EXAppExtensionAttributes", "EXExtensionPointIdentifier"},
	} {
		raw, _ := plist.Marshal(map[string]any{"CFBundleIdentifier": tc.id, "CFBundleDisplayName": tc.name, tc.key: map[string]any{tc.point: "com.apple.app-migration"}}, plist.BinaryFormat)
		files["Payload/Test.app/"+tc.path+"/Info.plist"] = raw
	}
	info, err := Inspect(archive(t, files))
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Extensions) != 2 || info.Extensions[0].Name != "Migrate" || info.Extensions[0].Path != "Extensions/Migrate.appex" || info.AppIDCount() != 3 {
		t.Fatalf("extension preview: %+v", info)
	}
	info.Selection = &ExtensionSelection{Included: []string{"org.example.fixture.share", "org.example.removed"}}
	if info.AppIDCount() != 2 || !reflect.DeepEqual(info.SelectedExtensions().Included, []string{"org.example.fixture.share"}) {
		t.Fatal("remembered choice enabled a new extension or counted a missing one")
	}
	info.Selection = &ExtensionSelection{}
	if info.AppIDCount() != 1 || len(info.SelectedExtensions().Included) != 0 {
		t.Fatal("explicit empty selection reverted to all")
	}
	info.Extensions = nil
	if info.AppIDCount() != 1 {
		t.Fatal("extension-free app cost is not one")
	}
}

func TestExtensionPreviewRejectsAmbiguousIdentifiers(t *testing.T) {
	files := map[string][]byte{"Payload/Test.app/Info.plist": infoBytes(t, plist.XMLFormat)}
	for _, name := range []string{"One", "Two"} {
		raw, _ := plist.Marshal(map[string]any{"CFBundleIdentifier": "org.example.fixture.share"}, plist.XMLFormat)
		files["Payload/Test.app/PlugIns/"+name+".appex/Info.plist"] = raw
	}
	if _, err := Inspect(archive(t, files)); err == nil {
		t.Fatal("duplicate extension identity accepted")
	}
}
