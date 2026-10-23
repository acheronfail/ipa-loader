package platform

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"howett.net/plist"
	"ipa-loader/app/internal/apple"
)

func TestCapabilitiesRequireNewProfileAuthorization(t *testing.T) {
	request, err := requestedCapabilities(map[string]any{
		"aps-environment":                          "production",
		"com.apple.developer.associated-domains":   []any{"applinks:youtube.com"},
		"com.apple.developer.siri":                 true,
		"com.apple.developer.networking.multicast": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, local := range []bool{false, true} {
		profile := map[string]any{"LocalProvision": local, "Entitlements": map[string]any{}}
		if !local {
			profile["Entitlements"] = map[string]any{
				"aps-environment":                        "development",
				"com.apple.developer.associated-domains": []any{"*"},
				"com.apple.developer.siri":               false,
			}
		}
		var messages []string
		e := newEngine(context.Background(), t.TempDir())
		e.message = func(s string) { messages = append(messages, s) }
		signing := map[string]any{"application-identifier": "NEW.org.example.app"}
		omitted := e.applyCapabilities("YouTube.app", profile, signing, request, nil)
		if local {
			if len(signing) != 1 || len(omitted) != 4 {
				t.Fatalf("free profile granted capabilities: %v", signing)
			}
		} else {
			if signing["aps-environment"] != "development" || !reflect.DeepEqual(signing["com.apple.developer.associated-domains"], []string{"applinks:youtube.com"}) || len(omitted) != 2 {
				t.Fatalf("capability policy mismatch: %v, %v", signing, omitted)
			}
			if !profileAuthorizes(mapField(profile, "Entitlements"), map[string]any{"com.apple.developer.associated-domains": signing["com.apple.developer.associated-domains"]}) {
				t.Fatal("preserved capabilities cannot refresh")
			}
		}
		if len(messages) != len(omitted) || !strings.Contains(messages[0], "not authorized by the new profile") {
			t.Fatal("omissions were not reported")
		}
		if request["aps-environment"] != "production" {
			t.Fatal("source request changed")
		}
	}
}

func TestMigrationExtensionProvisioningRetainsOnlyAuthorizedCode(t *testing.T) {
	for _, authorized := range []bool{false, true} {
		t.Run(map[bool]string{false: "omit", true: "preserve"}[authorized], func(t *testing.T) {
			ext := extensionMembers(t, "Migration", "org.example.fixture.migration")
			info, _ := dictionary(ext[0].data)
			delete(info, "NSExtension")
			info["EXAppExtensionAttributes"] = map[string]any{"EXExtensionPointIdentifier": "com.apple.app-migration"}
			ext[0].data, _ = plist.Marshal(info, plist.XMLFormat)
			request, _ := plist.Marshal(map[string]any{migrationAccessKey: []any{"org.example.fixture"}}, plist.XMLFormat)
			sig := super([]uint32{5}, [][]byte{blob(0xfade7171, request)})
			b := append(thin(), make([]byte, 16)...)
			binary.LittleEndian.PutUint32(b[16:], 2)
			binary.LittleEndian.PutUint32(b[20:], 40)
			binary.LittleEndian.PutUint32(b[56:], 0x1d)
			binary.LittleEndian.PutUint32(b[60:], 16)
			binary.LittleEndian.PutUint32(b[64:], uint32(len(b)))
			binary.LittleEndian.PutUint32(b[68:], uint32(len(sig)))
			ext[1].data = append(b, sig...)
			for i := range ext {
				ext[i].name = strings.Replace(ext[i].name, "/PlugIns/", "/Extensions/", 1)
			}
			m := append(members(t), ext...)
			m = append(m, frameworkMembers(t, "Payload/Fixture.app/Extensions/Migration.appex/Frameworks/Kit.framework")...)
			work := t.TempDir()
			app, err := extractIPA(context.Background(), writeIPA(t, m), work)
			if err != nil {
				t.Fatal(err)
			}
			ids, _ := standardBundleIdentity(app.BundleID, "TEAM")
			childIDs, _ := extensionIdentity("org.example.fixture.migration", ids)
			parent := extensionProfileFixture(ids.Registration, false, time.Now())
			child := extensionProfileFixture(childIDs.Registration, false, time.Now())
			if authorized {
				mapField(child, "Entitlements")[migrationAccessKey] = []any{ids.Installed}
			}
			encoded, _ := plist.Marshal(child, plist.XMLFormat)
			client := portalFunc(func(_ context.Context, _ *apple.Session, action string, _ map[string]any, _ string) (map[string]any, error) {
				switch action {
				case "listAppIds":
					return map[string]any{"appIds": []any{}}, nil
				case "addAppId":
					return map[string]any{"appId": map[string]any{"appIdId": "CHILD"}}, nil
				case "downloadTeamProvisioningProfile":
					return map[string]any{"provisioningProfile": map[string]any{"encodedProfile": []byte("synthetic CMS")}}, nil
				default:
					t.Fatalf("unexpected action %s", action)
					return nil, nil
				}
			})
			e := newControllerTestEngine(context.Background(), work)
			e.decodeProfile = func(string) ([]byte, error) { return encoded, nil }
			if err = e.prepareExtensions(&app, client, &apple.Session{}, fingerprint([]byte("test-cert")), "TEAM", "PHONE", ids, parent); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(app.Path, "Extensions", "Migration.appex")
			_, err = os.Stat(path)
			if authorized {
				if err != nil || len(app.Embedded) != 2 {
					t.Fatal("authorized migration code removed")
				}
				raw, err := os.ReadFile(app.Embedded[1].Entitlements)
				if err != nil {
					t.Fatal(err)
				}
				ent, _ := dictionary(raw)
				if !reflect.DeepEqual(textList(ent[migrationAccessKey]), []string{ids.Installed}) {
					t.Fatal("migration target was not mapped")
				}
			} else if !os.IsNotExist(err) || len(app.Embedded) != 0 {
				t.Fatal("unauthorized migration code remains in signing graph")
			}
			paths, err := refreshMemberPaths(app.Path)
			if err != nil || len(paths) != 1+map[bool]int{false: 0, true: 1}[authorized] {
				t.Fatalf("refresh graph mismatch: %v %v", paths, err)
			}
		})
	}
}

func TestCapabilityTypesAndUnknownEntitlements(t *testing.T) {
	for key, kind := range optionalCapabilityTypes {
		var valid any = true
		switch kind {
		case "environment":
			valid = "production"
		case "strings":
			valid = []string{"applinks:youtube.com"}
		case "bundles":
			valid = []string{"org.example.app"}
		}
		if err := basicEntitlements(map[string]any{key: valid}); err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		for _, invalid := range []any{nil, 7, map[string]any{}, []any{7}, ""} {
			if err := basicEntitlements(map[string]any{key: invalid}); err == nil {
				t.Fatalf("accepted malformed %s: %v", key, invalid)
			}
		}
	}
	if err := basicEntitlements(map[string]any{"com.apple.private.unknown": true}); err == nil {
		t.Fatal("unknown entitlement was silently omitted")
	}
}

func TestMigrationCapabilityMapsOnlyKnownInstalledIdentities(t *testing.T) {
	key := migrationAccessKey
	request := capabilityRequest{key: []string{"org.example.app"}}
	e := newEngine(context.Background(), t.TempDir())
	for _, tc := range []struct {
		allowed []any
		ids     map[string]string
		keep    bool
	}{
		{[]any{"org.example.app.TEAM"}, map[string]string{"org.example.app": "org.example.app.TEAM"}, true},
		{[]any{"org.example.app"}, map[string]string{"org.example.app": "org.example.app"}, true},
		{[]any{"org.example.app"}, map[string]string{"org.example.app": "org.example.app.TEAM"}, false},
		{[]any{"*"}, nil, false},
		{nil, map[string]string{"org.example.app": "org.example.app.TEAM"}, false},
	} {
		signing := map[string]any{}
		e.applyCapabilities("Migration.appex", map[string]any{"Entitlements": map[string]any{key: tc.allowed}}, signing, request, tc.ids)
		if (signing[key] != nil) != tc.keep {
			t.Fatalf("migration policy mismatch: %v", signing)
		}
	}
}
