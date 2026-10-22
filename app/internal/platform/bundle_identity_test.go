package platform

import (
	"strings"
	"testing"
	"time"
)

func TestStandardBundleIdentity(t *testing.T) {
	ids, err := standardBundleIdentity("org.example.fixture", "ABCDE12345")
	if err != nil || ids.Original != "org.example.fixture" || ids.Registration != "org.example.fixture.ABCDE12345" || ids.Installed != ids.Registration {
		t.Fatal("standard registration must append the literal team ID")
	}
	for _, args := range [][2]string{{"invalid", "TEAM"}, {"org.example.fixture", ""}, {"org.example.fixture", "TEAM.other"}, {"org.example.fixture", "TÉAM"}, {"org." + strings.Repeat("a", 247), "TEAM"}} {
		if _, err := standardBundleIdentity(args[0], args[1]); err == nil {
			t.Fatal("invalid or oversized identity accepted")
		}
	}
	ids, err = standardBundleIdentity("org."+strings.Repeat("a", 246), "TEAM")
	if err != nil || len(ids.Registration) != 255 {
		t.Fatal("boundary identifier truncated or rejected")
	}
}

func TestProfileDeterminesInstalledIdentity(t *testing.T) {
	base, _ := standardBundleIdentity("org.example.fixture", "TEAM")
	original := map[string]any{"bundleIdentifier": base.Original, "teamIdentifier": "TEAM"}
	suffixed := map[string]any{"bundleIdentifier": base.Registration, "signingInfo": map[string]any{"teamIdentifier": "TEAM"}}
	other := map[string]any{"bundleIdentifier": base.Original, "teamIdentifier": "OTHER"}
	otherSuffixed := map[string]any{"bundleIdentifier": base.Registration, "teamIdentifier": "OTHER"}
	for _, tc := range []struct {
		name      string
		profile   map[string]any
		installed []map[string]any
		want      string
		failure   bool
	}{
		{"free fresh", map[string]any{"LocalProvision": true}, nil, base.Registration, false},
		{"paid fresh", map[string]any{"LocalProvision": false}, nil, base.Original, false},
		{"paid absent LocalProvision", map[string]any{}, nil, base.Original, false},
		{"paid original update", map[string]any{}, []map[string]any{original}, base.Original, false},
		{"paid keeps suffixed update", map[string]any{}, []map[string]any{suffixed}, base.Registration, false},
		{"free suffixed update", map[string]any{"LocalProvision": true}, []map[string]any{suffixed}, base.Registration, false},
		{"free separate copy", map[string]any{"LocalProvision": true}, []map[string]any{other}, base.Registration, false},
		{"paid other team", map[string]any{}, []map[string]any{other}, "", true},
		{"suffixed other team", map[string]any{}, []map[string]any{otherSuffixed}, "", true},
		{"ambiguous paid copies", map[string]any{}, []map[string]any{original, suffixed}, "", true},
		{"malformed profile flag", map[string]any{"LocalProvision": "false"}, nil, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ids, err := base.withProfile(tc.profile, "TEAM", tc.installed)
			if tc.failure {
				if err == nil {
					t.Fatal("unsafe identity accepted")
				}
				return
			}
			if err != nil || ids.Installed != tc.want || ids.Registration != base.Registration {
				t.Fatal("installed/registration identity relationship changed")
			}
		})
	}
}

func TestResolvedProfileSeparatesInstalledAndAuthorizationIDs(t *testing.T) {
	ids, _ := standardBundleIdentity("org.example.fixture", "TEAM")
	now := time.Now()
	cert := []byte("synthetic certificate")
	groups := []any{"PREFIX.*", "synthetic.shared-group"}
	p := map[string]any{"Platform": []any{"iOS"}, "ExpirationDate": now.Add(time.Hour), "TeamIdentifier": []any{"TEAM"}, "ApplicationIdentifierPrefix": []any{"PREFIX"}, "DeveloperCertificates": []any{cert}, "ProvisionedDevices": []any{"PHONE"}, "Entitlements": map[string]any{"application-identifier": "PREFIX." + ids.Registration, "com.apple.developer.team-identifier": "TEAM", "keychain-access-groups": groups, "get-task-allow": true}}
	paid, err := ids.withProfile(p, "TEAM", nil)
	if err != nil {
		t.Fatal(err)
	}
	ent, err := validateResolvedProfile(p, fingerprint(cert), "TEAM", paid, "PHONE", now)
	if err != nil || paid.Installed != ids.Original || ent["application-identifier"] != "PREFIX."+ids.Registration {
		t.Fatal("paid authorization was incorrectly derived from installed metadata")
	}
	got := textList(ent["keychain-access-groups"])
	if len(got) != 2 || got[0] != groups[0] || got[1] != groups[1] {
		t.Fatal("paid profile keychain groups were changed")
	}
	p["LocalProvision"] = true
	if _, err = validateResolvedProfile(p, fingerprint(cert), "TEAM", paid, "PHONE", now); err == nil {
		t.Fatal("free profile authorized unmangled metadata")
	}
	free, err := ids.withProfile(p, "TEAM", nil)
	if err != nil {
		t.Fatal(err)
	}
	ent, err = validateResolvedProfile(p, fingerprint(cert), "TEAM", free, "PHONE", now)
	if err != nil || free.Installed != ids.Registration || ent["application-identifier"] != "PREFIX."+ids.Registration {
		t.Fatal("free identity relationship changed")
	}
	bad := free
	bad.Registration = ids.Original
	if _, err = validateResolvedProfile(p, fingerprint(cert), "TEAM", bad, "PHONE", now); err == nil {
		t.Fatal("unsuffixed registration accepted")
	}
	bad = free
	bad.Installed = "org.other.app"
	if _, err = validateResolvedProfile(p, fingerprint(cert), "TEAM", bad, "PHONE", now); err == nil {
		t.Fatal("unrelated installed identity accepted")
	}
	p["Entitlements"].(map[string]any)["application-identifier"] = "PREFIX." + ids.Original
	if _, err = validateResolvedProfile(p, fingerprint(cert), "TEAM", free, "PHONE", now); err == nil {
		t.Fatal("profile authorizing only the original ID was accepted")
	}
}
