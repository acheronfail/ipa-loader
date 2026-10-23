package platform

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"howett.net/plist"
	"ipa-loader/app/internal/apple"
	"ipa-loader/app/internal/ipa"
)

func TestExcludedExtensionsNeverReachProvisioning(t *testing.T) {
	m := append(members(t), extensionMembers(t, "Share", "org.example.fixture.share")...)
	excluded := extensionMembers(t, "Unused", "org.example.fixture.unused")
	excluded[1].data = []byte("unsupported executable that must not be inspected")
	m = append(m, excluded...)
	m = append(m, frameworkMembers(t, "Payload/Fixture.app/PlugIns/Unused.appex/Frameworks/Kit.framework")...)
	input := writeIPA(t, m)
	before, _ := os.ReadFile(input)
	ctx := WithExtensionSelection(context.Background(), &ipa.ExtensionSelection{Included: []string{"org.example.fixture.share"}})
	work := t.TempDir()
	app, err := extractIPA(ctx, input, work)
	if err != nil {
		t.Fatal(err)
	}
	if len(app.Embedded) != 1 || app.Embedded[0].Identifier != "org.example.fixture.share" {
		t.Fatalf("excluded code remains: %+v", app.Embedded)
	}
	if _, err = os.Stat(filepath.Join(app.Path, "PlugIns", "Unused.appex")); !os.IsNotExist(err) {
		t.Fatal("excluded extension was extracted")
	}
	ids, _ := standardBundleIdentity(app.BundleID, "TEAM")
	parent := extensionProfileFixture(ids.Registration, true, time.Now())
	childIDs, _ := extensionIdentity(app.Embedded[0].Identifier, ids)
	child := extensionProfileFixture(childIDs.Registration, true, time.Now())
	raw, _ := plist.Marshal(child, plist.XMLFormat)
	registrations := []string{}
	client := portalFunc(func(_ context.Context, _ *apple.Session, action string, params map[string]any, _ string) (map[string]any, error) {
		switch action {
		case "listAppIds":
			return map[string]any{"appIds": []any{}}, nil
		case "addAppId":
			registrations = append(registrations, stringField(params, "identifier"))
			return map[string]any{"appId": map[string]any{"appIdId": "SHARE"}}, nil
		case "downloadTeamProvisioningProfile":
			return map[string]any{"provisioningProfile": map[string]any{"encodedProfile": []byte("CMS")}}, nil
		default:
			t.Fatalf("unexpected action %s", action)
			return nil, nil
		}
	})
	e := newControllerTestEngine(ctx, work)
	e.decodeProfile = func(string) ([]byte, error) { return raw, nil }
	if err = e.prepareExtensions(&app, client, &apple.Session{}, fingerprint([]byte("test-cert")), "TEAM", "PHONE", ids, parent); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(registrations, []string{childIDs.Registration}) {
		t.Fatalf("registered excluded IDs: %v", registrations)
	}
	allOff := WithExtensionSelection(context.Background(), &ipa.ExtensionSelection{})
	app, err = extractIPA(allOff, input, t.TempDir())
	if err != nil || len(app.Embedded) != 0 {
		t.Fatalf("explicit all-off: %v %+v", err, app.Embedded)
	}
	if err = e.prepareExtensions(&app, nil, nil, "", "", "", ids, parent); err != nil {
		t.Fatal("all-off attempted provisioning: ", err)
	}
	after, _ := os.ReadFile(input)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("source IPA changed")
	}
}

func TestExtensionSelectionPersistenceAndIsolation(t *testing.T) {
	root := testPrivateTempDir(t)
	if choice, err := loadExtensionSelection(root, "user", "TEAM", "org.example.app"); err != nil || choice != nil {
		t.Fatal("missing preferences should include all")
	}
	for _, selection := range []*ipa.ExtensionSelection{{Included: []string{"org.example.app.share"}}, {Included: []string{}}} {
		if err := saveExtensionSelection(root, "Owner@Example.invalid", "TEAM", "org.example.app", selection); err != nil {
			t.Fatal(err)
		}
		actual, err := loadExtensionSelection(root, "owner@example.invalid", "TEAM", "org.example.app")
		if err != nil || actual == nil || !reflect.DeepEqual(actual.Included, selection.Included) {
			t.Fatalf("choice round trip: %+v %v", actual, err)
		}
		for _, key := range [][3]string{{"other", "TEAM", "org.example.app"}, {"owner@example.invalid", "OTHER", "org.example.app"}, {"owner@example.invalid", "TEAM", "org.example.other"}} {
			if choice, err := loadExtensionSelection(root, key[0], key[1], key[2]); err != nil || choice != nil {
				t.Fatal("choices leaked between accounts, teams or apps")
			}
		}
	}
	path := extensionChoicePath(root, "owner@example.invalid", "TEAM", "org.example.app")
	if err := os.WriteFile(path, []byte("bad JSON"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadExtensionSelection(root, "owner@example.invalid", "TEAM", "org.example.app"); err == nil {
		t.Fatal("corrupt saved choice silently enabled extensions")
	}
	selection := &ipa.ExtensionSelection{Included: []string{"org.example.app.share"}}
	ctx := WithExtensionSelection(context.Background(), selection)
	selection.Included[0] = "changed"
	copy := ExtensionSelection(ctx)
	copy.Included[0] = "changed again"
	if !reflect.DeepEqual(ExtensionSelection(ctx).Included, []string{"org.example.app.share"}) {
		t.Fatal("selection context did not snapshot user choices")
	}
}
