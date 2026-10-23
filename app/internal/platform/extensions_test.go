package platform

import (
	"context"
	"howett.net/plist"
	"ipa-loader/app/internal/apple"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func extensionMembers(t *testing.T, name, id string) []zipMember {
	t.Helper()
	info, err := plist.Marshal(map[string]any{"CFBundleExecutable": "Share", "CFBundleIdentifier": id, "CFBundleShortVersionString": "1.0", "CFBundleVersion": "1", "CFBundlePackageType": "XPC!", "NSExtension": map[string]any{"NSExtensionPointIdentifier": "com.apple.share-services", "NSExtensionPrincipalClass": "ShareController"}}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	base := "Payload/Fixture.app/PlugIns/" + name + ".appex/"
	return []zipMember{{base + "Info.plist", info, 0}, {base + "Share", thin(), 0}}
}

func TestExtensionDiscoveryAndNestedLibraries(t *testing.T) {
	m := append(members(t), extensionMembers(t, "Share", "org.example.fixture.share")...)
	m = append(m, extensionMembers(t, "Action", "org.example.fixture.action")...)
	m = append(m, frameworkMembers(t, "Payload/Fixture.app/PlugIns/Share.appex/Frameworks/Kit.framework")...)
	a, err := extractIPA(context.Background(), writeIPA(t, m), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Embedded) != 3 || a.Embedded[0].Extension || !a.Embedded[1].Extension || !a.Embedded[2].Extension {
		t.Fatal("extensions/libraries not ordered inside out")
	}
}

func TestExtensionMetadataRejectsBrokenRelationship(t *testing.T) {
	for _, kind := range []string{"unrelated ID", "duplicate ID", "missing build", "missing extension point", "wrong package", "missing executable", "misplaced", "nested extension", "legacy in Extensions", "modern in PlugIns"} {
		t.Run(kind, func(t *testing.T) {
			ext := extensionMembers(t, "Share", "org.example.fixture.share")
			info, _ := dictionary(ext[0].data)
			switch kind {
			case "unrelated ID":
				info["CFBundleIdentifier"] = "org.example.other.share"
			case "missing build":
				delete(info, "CFBundleVersion")
			case "missing extension point":
				delete(info, "NSExtension")
			case "wrong package":
				info["CFBundlePackageType"] = "APPL"
			case "missing executable":
				info["CFBundleExecutable"] = "Missing"
			case "misplaced":
				for i := range ext {
					ext[i].name = strings.Replace(ext[i].name, "/PlugIns/", "/Resources/", 1)
				}
			case "nested extension":
				for i := range ext {
					ext[i].name = strings.Replace(ext[i].name, "/Share.appex/", "/Parent.appex/PlugIns/Share.appex/", 1)
				}
			case "legacy in Extensions":
				for i := range ext {
					ext[i].name = strings.Replace(ext[i].name, "/PlugIns/", "/Extensions/", 1)
				}
			case "modern in PlugIns":
				delete(info, "NSExtension")
				info["EXAppExtensionAttributes"] = map[string]any{"EXExtensionPointIdentifier": "com.apple.app-migration"}
			}
			ext[0].data, _ = plist.Marshal(info, plist.XMLFormat)
			m := append(members(t), ext...)
			if kind == "duplicate ID" {
				m = append(m, extensionMembers(t, "Another", "org.example.fixture.share")...)
			}
			if _, err := extractIPA(context.Background(), writeIPA(t, m), t.TempDir()); err == nil {
				t.Fatal("invalid extension accepted")
			}
		})
	}
}

func TestExtensionFoundationDiscoveryAndRefresh(t *testing.T) {
	ext := extensionMembers(t, "Migration", "org.example.fixture.migration")
	info, _ := dictionary(ext[0].data)
	delete(info, "NSExtension")
	info["EXAppExtensionAttributes"] = map[string]any{"EXExtensionPointIdentifier": "com.apple.app-migration"}
	ext[0].data, _ = plist.Marshal(info, plist.XMLFormat)
	for i := range ext {
		ext[i].name = strings.Replace(ext[i].name, "/PlugIns/", "/Extensions/", 1)
	}
	m := append(members(t), ext...)
	m = append(m, extensionMembers(t, "Share", "org.example.fixture.share")...)
	m = append(m, frameworkMembers(t, "Payload/Fixture.app/Extensions/Migration.appex/Frameworks/Kit.framework")...)
	app, err := extractIPA(context.Background(), writeIPA(t, m), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(app.Embedded) != 3 || app.Embedded[0].Extension || !app.Embedded[1].Extension || !app.Embedded[2].Extension {
		t.Fatal("modern extension signing graph is incomplete or not ordered inside out")
	}
	paths, err := refreshMemberPaths(app.Path)
	if err != nil || len(paths) != 3 {
		t.Fatalf("refresh graph omitted an extension: %v, %v", paths, err)
	}
}

func extensionProfileFixture(registration string, local bool, now time.Time) map[string]any {
	return map[string]any{"Platform": []any{"iOS"}, "ExpirationDate": now.Add(time.Hour), "TeamIdentifier": []any{"TEAM"}, "ApplicationIdentifierPrefix": []any{"PREFIX"}, "DeveloperCertificates": []any{[]byte("test-cert")}, "ProvisionedDevices": []any{"PHONE"}, "LocalProvision": local, "Entitlements": map[string]any{"application-identifier": "PREFIX." + registration, "com.apple.developer.team-identifier": "TEAM", "keychain-access-groups": []any{"PREFIX.*"}, "get-task-allow": true}}
}

func TestExtensionIdentityAndProfileModes(t *testing.T) {
	now := time.Now()
	for _, mode := range []string{"free", "paid", "paid existing suffix"} {
		t.Run(mode, func(t *testing.T) {
			parent, _ := standardBundleIdentity("org.example.fixture", "TEAM")
			if mode == "paid" {
				parent.Installed = parent.Original
			}
			ids, err := extensionIdentity("org.example.fixture.share", parent)
			if err != nil {
				t.Fatal(err)
			}
			if ids.Registration != "org.example.fixture.TEAM.share" || ids.Installed != parent.Installed+".share" {
				t.Fatal("extension no longer follows parent ID")
			}
			p := extensionProfileFixture(parent.Registration, mode == "free", now)
			child := extensionProfileFixture(ids.Registration, mode == "free", now)
			ent, err := validateExtensionProfile(p, child, fingerprint([]byte("test-cert")), "TEAM", "PHONE", ids, now)
			if err != nil || ent["application-identifier"] != "PREFIX."+ids.Registration {
				t.Fatal("profile failed:", err)
			}
			child["LocalProvision"] = mode != "free"
			if _, err = validateExtensionProfile(p, child, fingerprint([]byte("test-cert")), "TEAM", "PHONE", ids, now); err == nil {
				t.Fatal("mixed free/paid profiles accepted")
			}
		})
	}
	parent, _ := standardBundleIdentity("org.example.fixture", "TEAM")
	if _, err := extensionIdentity("org.example.other.share", parent); err == nil {
		t.Fatal("unrelated extension accepted")
	}
	if _, err := extensionIdentity(parent.Original+"."+strings.Repeat("x", 230), parent); err != nil {
		t.Fatal("255-character registration rejected:", err)
	}
	if _, err := extensionIdentity(parent.Original+"."+strings.Repeat("x", 231), parent); err == nil {
		t.Fatal("overlong registration accepted")
	}
}

func TestExtensionProfileRejectsWrongAuthorization(t *testing.T) {
	now := time.Now()
	parentIDs, _ := standardBundleIdentity("org.example.fixture", "TEAM")
	parentIDs.Installed = parentIDs.Original
	ids, _ := extensionIdentity(parentIDs.Original+".share", parentIDs)
	for _, kind := range []string{"prefix", "certificate", "team", "device", "expired", "parent authorization", "debug", "account type"} {
		t.Run(kind, func(t *testing.T) {
			parent := extensionProfileFixture(parentIDs.Registration, false, now)
			child := extensionProfileFixture(ids.Registration, false, now)
			switch kind {
			case "prefix":
				child["ApplicationIdentifierPrefix"] = []any{"OTHER"}
			case "certificate":
				child["DeveloperCertificates"] = []any{[]byte("other-cert")}
			case "team":
				child["TeamIdentifier"] = []any{"OTHER"}
			case "device":
				child["ProvisionedDevices"] = []any{"OTHER"}
			case "expired":
				child["ExpirationDate"] = now.Add(-time.Second)
			case "parent authorization":
				mapField(child, "Entitlements")["application-identifier"] = "PREFIX." + parentIDs.Registration
			case "debug":
				mapField(child, "Entitlements")["get-task-allow"] = false
			case "account type":
				child["LocalProvision"] = "false"
			}
			if _, err := validateExtensionProfile(parent, child, fingerprint([]byte("test-cert")), "TEAM", "PHONE", ids, now); err == nil {
				t.Fatal("invalid extension profile accepted")
			}
		})
	}
}

func TestExtensionSigningRequiresProvisioning(t *testing.T) {
	e := newControllerTestEngine(context.Background(), t.TempDir())
	called := false
	e.run = func(string, ...string) ([]byte, []byte, error) { called = true; return nil, nil, nil }
	if err := e.signApp(appInfo{Embedded: []codeObject{{Extension: true}}}, "CERT", "parent-entitlements"); err == nil || called {
		t.Fatal("unprovisioned extension reached signing")
	}
}

func TestDefaultPaidInputKeychainGroups(t *testing.T) {
	for _, groups := range [][]any{{"PREFIX.org.example.app.share"}, {"PREFIX.*", "com.apple.token"}} {
		if err := basicEntitlements(map[string]any{"application-identifier": "PREFIX.org.example.app.share", "keychain-access-groups": groups}); err != nil {
			t.Fatal(err)
		}
	}
	for _, groups := range [][]any{{"OTHER.*"}, {"PREFIX.custom*shared-group"}, {"PREFIX.*", "PREFIX.*"}} {
		if err := basicEntitlements(map[string]any{"application-identifier": "PREFIX.org.example.app.share", "keychain-access-groups": groups}); err == nil {
			t.Fatal("custom or duplicate keychain groups accepted")
		}
	}
}

func TestExtensionProvisioningUsesSelectedIdentityAndOwnProfile(t *testing.T) {
	work := t.TempDir()
	m := members(t)
	// Model a repacked app whose extension still has its original version.
	info, _ := dictionary(m[0].data)
	info["CFBundleShortVersionString"], info["CFBundleVersion"] = "21.39.4", "21.39.4"
	m[0].data, _ = plist.Marshal(info, plist.XMLFormat)
	app, err := extractIPA(context.Background(), writeIPA(t, append(m, extensionMembers(t, "Share", "org.example.fixture.share")...)), work)
	if err != nil {
		t.Fatal(err)
	}
	ids, _ := standardBundleIdentity(app.BundleID, "TEAM")
	ids.Installed = ids.Original
	p := extensionProfileFixture(ids.Registration, false, time.Now())
	childIDs, _ := extensionIdentity(app.Embedded[0].Identifier, ids)
	child := extensionProfileFixture(childIDs.Registration, false, time.Now())
	encoded, _ := plist.Marshal(child, plist.XMLFormat)
	var actions []string
	client := portalFunc(func(ctx context.Context, s *apple.Session, action string, params map[string]any, team string) (map[string]any, error) {
		actions = append(actions, action)
		switch action {
		case "listAppIds":
			return map[string]any{"appIds": []any{}}, nil
		case "addAppId":
			if params["identifier"] != childIDs.Registration {
				t.Fatal("wrong extension registration")
			}
			return map[string]any{"appId": map[string]any{"appIdId": "CHILD"}}, nil
		case "downloadTeamProvisioningProfile":
			return map[string]any{"provisioningProfile": map[string]any{"encodedProfile": []byte("synthetic CMS")}}, nil
		default:
			t.Fatal("extension changed certificate/device state:", action)
			return nil, nil
		}
	})
	e := newControllerTestEngine(context.Background(), work)
	e.decodeProfile = func(string) ([]byte, error) { return encoded, nil }
	if err = e.prepareExtensions(&app, client, &apple.Session{}, fingerprint([]byte("test-cert")), "TEAM", "PHONE", ids, p); err != nil {
		t.Fatal(err)
	}
	object := app.Embedded[0]
	metadataRaw, err := os.ReadFile(filepath.Join(object.Path, "Info.plist"))
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := dictionary(metadataRaw)
	if err != nil || stringField(metadata, "CFBundleShortVersionString") != app.Version || stringField(metadata, "CFBundleVersion") != app.Build {
		t.Fatal("extension version was not aligned before signing")
	}
	if len(actions) != 3 || object.Identifier != childIDs.Installed || object.Entitlements == "" {
		t.Fatal("extension was not provisioned independently")
	}
	data, err := os.ReadFile(object.Entitlements)
	if err != nil {
		t.Fatal(err)
	}
	ent, _ := dictionary(data)
	if ent["application-identifier"] != "PREFIX."+childIDs.Registration {
		t.Fatal("extension inherited parent authorization")
	}
	if _, err = os.Stat(filepath.Join(object.Path, "embedded.mobileprovision")); err != nil {
		t.Fatal(err)
	}
}
