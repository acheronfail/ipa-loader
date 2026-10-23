package platform

import (
	"context"
	"howett.net/plist"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestFreeSharingFallbackSurvivesResigningAndPaidUpgrade(t *testing.T) {
	work := t.TempDir()
	root := filepath.Join(work, "Fixture.app")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	info, _ := plist.Marshal(map[string]any{"CFBundleIdentifier": "org.example.app.TEAM"}, plist.XMLFormat)
	if err := os.WriteFile(filepath.Join(root, "Info.plist"), info, 0600); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "Fixture")
	if err := os.WriteFile(executable, sharingMachO(), 0600); err != nil {
		t.Fatal(err)
	}
	adapter := filepath.Join(work, "adapter.dylib")
	if err := os.WriteFile(adapter, library(), 0600); err != nil {
		t.Fatal(err)
	}
	ctx := &sharingContext{Adapter: adapter, Registrations: map[string]string{"org.example.app": "org.example.app.TEAM"}}
	request, err := requestedSharing(map[string]any{"application-identifier": "OLD.org.example.app", "com.apple.security.application-groups": []any{"group.org.example.shared"}, "keychain-access-groups": []any{"OLD.org.example.app", "OLD.org.example.sso"}})
	if err != nil {
		t.Fatal(err)
	}
	profile := map[string]any{"LocalProvision": true, "ApplicationIdentifierPrefix": []any{"PREFIX"}, "Entitlements": map[string]any{"keychain-access-groups": []any{"PREFIX.org.example.app.TEAM"}}}
	plan, err := sharingFor(request, "TEAM", "org.example.app.TEAM", profile, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.AppGroups) != 0 || len(plan.AppGroupAliases) != 0 || plan.LocalAppGroups["group.org.example.shared"] != "group.org.example.shared.TEAM" || plan.KeychainAliases["OLD.org.example.sso"] != "PREFIX.org.example.app.TEAM" {
		t.Fatalf("free storage plan: %+v", plan)
	}
	e := newEngine(context.Background(), work)
	signing := map[string]any{}
	if err = e.applySharing(root, executable, profile, signing, plan, ctx); err != nil {
		t.Fatal(err)
	}
	if signing["com.apple.security.application-groups"] != nil {
		t.Fatal("free signing claimed app-group access")
	}
	request, err = readSharingRequest(executable)
	if err != nil || !reflect.DeepEqual(request.AppGroups, []string{"group.org.example.shared"}) {
		t.Fatalf("local group requests lost: %+v %v", request, err)
	}
	plan, err = sharingFor(request, "TEAM", "org.example.app.TEAM", profile, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.applySharing(root, executable, profile, map[string]any{}, plan, ctx); err != nil {
		t.Fatal("free re-signing: ", err)
	}
	profile["LocalProvision"] = false
	mapField(profile, "Entitlements")["com.apple.security.application-groups"] = []any{"group.org.example.shared.TEAM"}
	plan, err = sharingFor(request, "TEAM", "org.example.app.TEAM", profile, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.LocalAppGroups) != 0 || len(plan.AppGroups) != 1 {
		t.Fatal("paid upgrade retained free fallback")
	}
	if err = e.applySharing(root, executable, profile, map[string]any{}, plan, ctx); err != nil {
		t.Fatal("paid upgrade: ", err)
	}
}

func TestSharingPlanPreservesMainExtensionRelationships(t *testing.T) {
	makePlan := func(app, registration string) sharingPlan {
		r, err := requestedSharing(map[string]any{"application-identifier": "OLD." + app, "com.apple.security.application-groups": []any{"group.org.example.shared"}, "keychain-access-groups": []any{"OLD." + app, "OLD.org.example.shared"}})
		if err != nil {
			t.Fatal(err)
		}
		p, err := planSharing(r, "TEAM", "PREFIX", registration, map[string]string{"org.example.app": "org.example.app.TEAM", "org.example.app.share": "org.example.app.TEAM.share"})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	parent := makePlan("org.example.app", "org.example.app.TEAM")
	child := makePlan("org.example.app.share", "org.example.app.TEAM.share")
	if !reflect.DeepEqual(parent.AppGroups, child.AppGroups) || parent.AppGroups[0] != "group.org.example.shared.TEAM" {
		t.Fatal("shared app group diverged")
	}
	if parent.KeychainAliases["OLD.org.example.shared"] != child.KeychainAliases["OLD.org.example.shared"] {
		t.Fatal("shared keychain mapping diverged")
	}
	if parent.KeychainGroups[0] == child.KeychainGroups[0] {
		t.Fatal("default keychain group must remain per-bundle")
	}
	profile := map[string]any{"Entitlements": map[string]any{"com.apple.security.application-groups": []any{"group.org.example.shared.TEAM"}, "keychain-access-groups": []any{"PREFIX.*"}}}
	if err := authorizeSharing(profile, parent); err != nil {
		t.Fatal(err)
	}
	if err := authorizeSharing(profile, child); err != nil {
		t.Fatal(err)
	}
	delete(profile["Entitlements"].(map[string]any), "com.apple.security.application-groups")
	if err := authorizeSharing(profile, parent); err == nil {
		t.Fatal("missing app group authorization accepted")
	}
}

func TestSharingRequestValidation(t *testing.T) {
	for _, value := range []any{true, []any{7}, []any{"group.org.example.a", "group.org.example.a"}, []any{"not-a-group"}, []any{"group.org.example.*"}, []any{"group.org.example.a\n"}} {
		if _, err := requestedSharing(map[string]any{"com.apple.security.application-groups": value}); err == nil {
			t.Fatal("invalid app groups accepted")
		}
	}
	for _, value := range []any{[]any{"FOREIGN.org.example.shared"}, []any{"OLD.*.bad"}, []any{"OLD.org.example.shared", "OLD.org.example.shared"}} {
		if _, err := requestedSharing(map[string]any{"application-identifier": "OLD.org.example.app", "keychain-access-groups": value}); err == nil {
			t.Fatal("invalid shared keychain groups accepted")
		}
	}
	if _, err := requestedSharing(map[string]any{"keychain-access-groups": []any{"OLD.org.example.shared"}}); err == nil {
		t.Fatal("keychain groups accepted without original identity")
	}
}

func TestSharingRejectsUnauthorizedProfileGroups(t *testing.T) {
	r, _ := requestedSharing(map[string]any{"application-identifier": "OLD.org.example.app", "keychain-access-groups": []any{"OLD.org.example.shared"}})
	p, err := planSharing(r, "TEAM", "PREFIX", "org.example.app.TEAM", nil)
	if err != nil {
		t.Fatal(err)
	}
	profile := map[string]any{"Entitlements": map[string]any{"keychain-access-groups": []any{"OTHER.*"}}}
	if err = authorizeSharing(profile, p); err == nil {
		t.Fatal("foreign prefix authorized")
	}
	profile["Entitlements"].(map[string]any)["keychain-access-groups"] = []any{"PREFIX.org.example.app.TEAM"}
	if err = authorizeSharing(profile, p); err == nil {
		t.Fatal("shared group absent from profile accepted")
	}
}

func TestSharingMapsParentDefaultGroupForExtension(t *testing.T) {
	r, err := requestedSharing(map[string]any{"application-identifier": "OLD.org.example.app.share", "keychain-access-groups": []any{"OLD.org.example.app"}, "com.apple.security.application-groups": []any{"group.org.example.shared.TEAM"}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := planSharing(r, "TEAM", "PREFIX", "org.example.app.TEAM.share", map[string]string{"org.example.app": "org.example.app.TEAM"})
	if err != nil {
		t.Fatal(err)
	}
	if p.KeychainAliases["OLD.org.example.app"] != "PREFIX.org.example.app.TEAM" {
		t.Fatal("extension did not map the parent's default keychain group")
	}
	if p.AppGroups[0] != "group.org.example.shared.TEAM" {
		t.Fatal("re-signing duplicated the group suffix")
	}
}

func TestSharingMetadataRejectsUnsupportedOrMalformedAliases(t *testing.T) {
	for _, value := range []any{
		true,
		map[string]any{"Version": 2, "AppGroups": map[string]any{}, "KeychainGroups": map[string]any{}},
		map[string]any{"Version": 1},
		map[string]any{"Version": 1, "AppGroups": map[string]any{"group.org.example.a": true}, "KeychainGroups": map[string]any{}},
		map[string]any{"Version": 1, "AppGroups": map[string]any{}, "KeychainGroups": map[string]any{"OLD.org.example.a\n": "NEW.org.example.a"}},
	} {
		if _, err := sharingMetadata(map[string]any{"IPALoaderSharing": value}); err == nil {
			t.Fatal("invalid existing aliases accepted before provisioning")
		}
	}
	if managed, err := sharingMetadata(map[string]any{"IPALoaderSharing": map[string]any{"Version": uint64(1), "AppGroups": map[string]any{}, "KeychainGroups": map[string]any{"OLD.org.example.a": "NEW.org.example.a"}}}); err != nil || !managed {
		t.Fatal("valid existing sharing aliases rejected")
	}
}
