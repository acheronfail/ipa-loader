package platform

import (
	"testing"
	"time"
)

func TestInventoryExpiryDoesNotGuess(t *testing.T) {
	expiry := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	item := map[string]any{"ApplicationIdentifier": "TEAM.org.example.app"}
	profile := func(id string, date time.Time) map[string]any {
		return map[string]any{"Entitlements": map[string]any{"application-identifier": id}, "ExpirationDate": date}
	}
	tests := []struct {
		name     string
		profiles []map[string]any
		want     time.Time
	}{
		{"exact", []map[string]any{profile("TEAM.org.example.app", expiry)}, expiry},
		{"wildcard", []map[string]any{profile("TEAM.org.example.*", expiry)}, expiry},
		{"wrong prefix", []map[string]any{profile("OTHER.org.example.app", expiry)}, time.Time{}},
		{"ambiguous", []map[string]any{profile("TEAM.org.example.app", expiry), profile("TEAM.org.example.app", expiry.Add(time.Hour))}, time.Time{}},
		{"duplicates", []map[string]any{profile("TEAM.org.example.app", expiry), profile("TEAM.org.example.app", expiry)}, expiry},
		{"unavailable", nil, time.Time{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := inventoryAppExpiry(item, tc.profiles); !got.Equal(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
func TestReconcileAppsKeepsHistoryOnlyForMatchingInstall(t *testing.T) {
	expiry := time.Now().UTC().Add(7 * 24 * time.Hour)
	refreshed := expiry.Add(-7 * 24 * time.Hour)
	record := iosAppRecord{IOSApp: IOSApp{BundleID: "org.example.tracked", Name: "Tracked", Version: "1", Build: "1", Expires: expiry, Refreshed: refreshed}, Package: "original.ipa"}
	records := map[string]iosAppRecord{record.BundleID: record, "org.example.removed": {IOSApp: IOSApp{BundleID: "org.example.removed"}}}
	item := map[string]any{"CFBundleIdentifier": record.BundleID, "CFBundleShortVersionString": "1", "CFBundleVersion": "1"}
	apps := reconcileIOSApps(records, []map[string]any{item,
		{"CFBundleIdentifier": "org.example.store"},
		{"CFBundleIdentifier": "org.example.external", "Entitlements": map[string]any{"get-task-allow": true}},
	}, nil)
	if len(apps) != 2 || !apps[record.BundleID].Refreshed.Equal(refreshed) {
		t.Fatal("lost confirmed history or included an App Store/deleted app")
	}
	if !apps["org.example.external"].Refreshed.IsZero() || !apps["org.example.external"].Expires.IsZero() {
		t.Fatal("invented external app dates")
	}
	item["CFBundleVersion"] = "2"
	changed := reconcileIOSApps(records, []map[string]any{item}, nil)[record.BundleID]
	if !changed.Expires.IsZero() || !changed.Refreshed.IsZero() {
		t.Fatal("retained dates for a replaced app")
	}
	item["CFBundleVersion"] = "1"
	item["ApplicationIdentifier"] = "TEAM." + record.BundleID
	profiles := []map[string]any{{"Entitlements": map[string]any{"application-identifier": "TEAM." + record.BundleID}, "ExpirationDate": expiry.Add(time.Hour)}}
	changed = reconcileIOSApps(records, []map[string]any{item}, profiles)[record.BundleID]
	if !changed.Refreshed.IsZero() || !changed.Expires.Equal(expiry.Add(time.Hour)) {
		t.Fatal("claimed previous refresh after profile replacement")
	}
}

func TestAppAccountComesOnlyFromMatchingInstallHistory(t *testing.T) {
	expiry := time.Now().UTC().Add(7 * 24 * time.Hour)
	record := iosAppRecord{IOSApp: IOSApp{BundleID: "org.example.app", Version: "1", Build: "1", Team: "TEAM", Account: "owner@example.invalid", Expires: expiry}}
	records := map[string]iosAppRecord{record.BundleID: record}
	item := map[string]any{"CFBundleIdentifier": record.BundleID, "CFBundleShortVersionString": "1", "CFBundleVersion": "1", "Entitlements": map[string]any{"com.apple.developer.team-identifier": "TEAM", "get-task-allow": true, "application-identifier": "TEAM." + record.BundleID}}
	profile := map[string]any{"Entitlements": map[string]any{"application-identifier": "TEAM." + record.BundleID}, "ExpirationDate": expiry}
	if got := reconcileIOSApps(records, []map[string]any{item}, []map[string]any{profile})[record.BundleID]; got.Account != record.Account {
		t.Fatal("lost the recorded installation account")
	}
	if got := reconcileIOSApps(nil, []map[string]any{item}, []map[string]any{profile})[record.BundleID]; got.Account != "" {
		t.Fatal("invented an account from a developer team")
	}
	item["CFBundleVersion"] = "2"
	if got := reconcileIOSApps(records, []map[string]any{item}, nil)[record.BundleID]; got.Account != "" {
		t.Fatal("kept the previous account after replacement")
	}
	item["CFBundleVersion"] = "1"
	profile["ExpirationDate"] = expiry.Add(time.Hour)
	if got := reconcileIOSApps(records, []map[string]any{item}, []map[string]any{profile})[record.BundleID]; got.Account != "" {
		t.Fatal("kept the previous account after external re-signing")
	}
	item["Entitlements"] = map[string]any{"com.apple.developer.team-identifier": "OTHER"}
	if got := reconcileIOSApps(records, []map[string]any{item}, nil)[record.BundleID]; got.Account != "" || got.Team != "OTHER" {
		t.Fatal("kept account attribution from another team")
	}
}

func TestMatchingParentProfilePreservesAccountAndEarlierExtensionDeadline(t *testing.T) {
	parent := time.Now().UTC().Add(7 * 24 * time.Hour)
	earlier := parent.Add(-24 * time.Hour)
	record := iosAppRecord{IOSApp: IOSApp{BundleID: "org.example.app", Version: "1", Build: "1", Account: "owner@example.invalid", Expires: earlier}, ProfileExpires: parent}
	item := map[string]any{"CFBundleIdentifier": record.BundleID, "CFBundleShortVersionString": "1", "CFBundleVersion": "1", "ApplicationIdentifier": "TEAM." + record.BundleID}
	profile := map[string]any{"Entitlements": map[string]any{"application-identifier": "TEAM." + record.BundleID}, "ExpirationDate": parent}
	app := reconcileIOSApps(map[string]iosAppRecord{record.BundleID: record}, []map[string]any{item}, []map[string]any{profile})[record.BundleID]
	if app.Account != record.Account || !app.Expires.Equal(earlier) {
		t.Fatal("a matching parent profile lost attribution or extended the app's deadline")
	}
}

func TestReplacingRefreshBindingDiscardsPreviousReceipt(t *testing.T) {
	original := &refreshBinding{BundleID: "org.ipaloader.ios", Build: "14"}
	receipt := &profileRefreshReceipt{Account: "account@example.invalid"}
	record := iosAppRecord{Binding: original, ProfileRefresh: receipt}
	same := *original
	record.setRefreshBinding(&same)
	if record.ProfileRefresh != receipt {
		t.Fatal("matching code lost its receipt")
	}
	replacement := same
	replacement.Build = "15"
	record.setRefreshBinding(&replacement)
	if record.ProfileRefresh != nil || record.Binding != &replacement {
		t.Fatal("replacement retained an unrelated receipt")
	}
}
