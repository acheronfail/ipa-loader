package platform

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"testing"
	"time"

	"howett.net/plist"
	"ipa-loader/app/internal/apple"
)

type refreshTestRig struct {
	binding                    *refreshBinding
	profilesByRaw              map[string]map[string]any
	downloaded                 [][]byte
	stored                     [][]byte
	installs                   int
	inventories                int
	requests                   []string
	extraAppIDs                []map[string]any
	certRevoked                bool
	requestErr, errorOnInstall error
	rejected                   bool
	omitReadback               bool
	changedOnReadback          bool
	decodeErr                  bool
	createdDuringDownload      bool
}

func newRefreshRig(t *testing.T, extension bool) *refreshTestRig {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{OrganizationalUnit: []string{"TESTTEAM10"}}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	binding := &refreshBinding{BundleID: "org.example.app.TESTTEAM10", Version: "1", Build: "1", Team: "TESTTEAM10", Certificate: der}
	rig := &refreshTestRig{binding: binding, profilesByRaw: map[string]map[string]any{}}
	ids := []string{binding.BundleID}
	if extension {
		ids = append(ids, binding.BundleID+".widget")
	}
	for i, id := range ids {
		ent := map[string]any{"application-identifier": binding.Team + "." + id, "com.apple.developer.team-identifier": binding.Team, "get-task-allow": true, "keychain-access-groups": []any{binding.Team + "." + id}}
		raw, err := plist.Marshal(ent, plist.XMLFormat)
		if err != nil {
			t.Fatal(err)
		}
		binding.Members = append(binding.Members, refreshMember{BundleID: id, Registration: id, Entitlements: raw, Expires: now.Add(24 * time.Hour)})
		profile := map[string]any{"Platform": []any{"iOS"}, "ExpirationDate": now.Add(7 * 24 * time.Hour), "CreationDate": now.Add(-time.Minute), "TeamIdentifier": []any{binding.Team}, "ApplicationIdentifierPrefix": []any{binding.Team}, "DeveloperCertificates": []any{der}, "ProvisionedDevices": []any{"PHONE"}, "LocalProvision": true, "Entitlements": ent}
		data := []byte(fmt.Sprintf("profile-%d", i))
		rig.profilesByRaw[string(data)] = profile
		rig.downloaded = append(rig.downloaded, data)
	}
	return rig
}
func (r *refreshTestRig) Request(ctx context.Context, session *apple.Session, action string, body map[string]any, team string) (map[string]any, error) {
	r.requests = append(r.requests, action)
	if r.requestErr != nil {
		return nil, r.requestErr
	}
	switch action {
	case "listAllDevelopmentCerts":
		return map[string]any{"certificates": []any{map[string]any{"certContent": r.binding.Certificate, "revoked": r.certRevoked}}}, nil
	case "listAppIds":
		var list []any
		for i, m := range r.binding.Members {
			list = append(list, map[string]any{"identifier": m.Registration, "appIdId": fmt.Sprintf("ID-%d", i)})
		}
		for _, record := range r.extraAppIDs {
			list = append(list, record)
		}
		return map[string]any{"appIds": list}, nil
	case "downloadTeamProvisioningProfile":
		var i int
		fmt.Sscanf(body["appIdId"].(string), "ID-%d", &i)
		if r.createdDuringDownload {
			r.profilesByRaw[string(r.downloaded[i])]["CreationDate"] = time.Now().UTC()
		}
		return map[string]any{"provisioningProfile": map[string]any{"encodedProfile": r.downloaded[i]}}, nil
	default:
		return nil, errors.New("unexpected portal mutation: " + action)
	}
}
func (r *refreshTestRig) io() profileRefreshIO {
	return profileRefreshIO{
		inventory: func(context.Context) ([]map[string]any, error) {
			r.inventories++
			ent, _ := dictionary(r.binding.Members[0].Entitlements)
			version := r.binding.Version
			if r.changedOnReadback && r.inventories >= 3 {
				version = "2"
			}
			return []map[string]any{{"CFBundleIdentifier": r.binding.BundleID, "CFBundleShortVersionString": version, "CFBundleVersion": r.binding.Build, "Entitlements": ent}}, nil
		},
		decode: func(raw []byte) (map[string]any, error) {
			if r.decodeErr {
				return nil, errors.New("invalid CMS")
			}
			return r.profilesByRaw[string(raw)], nil
		},
		install: func(ctx context.Context, raw []byte) error {
			r.installs++
			// A lost acknowledgement can happen after the phone accepted the profile.
			if !r.rejected {
				r.stored = append(r.stored, raw)
			}
			return r.errorOnInstall
		},
		profiles: func(context.Context) ([][]byte, error) {
			if r.omitReadback {
				return nil, nil
			}
			return r.stored, nil
		},
		rejected: func(error) bool { return r.rejected },
	}
}
func (r *refreshTestRig) run(ctx context.Context, prior *profileRefreshReceipt) (*profileRefreshReceipt, error) {
	return refreshProfiles(ctx, r, &apple.Session{Username: "owner@example.invalid"}, r.binding, prior, "PHONE", r.io(), nil)
}
func TestProfileRefreshRenewsParentAndExtensionsWithoutSigning(t *testing.T) {
	r := newRefreshRig(t, true)
	receipt, err := r.run(context.Background(), nil)
	if err != nil || receipt == nil {
		t.Fatalf("refresh: %+v %v", receipt, err)
	}
	if r.installs != 2 || len(receipt.Hashes) != 2 || receipt.Refreshed.IsZero() || receipt.Account != "owner@example.invalid" {
		t.Fatal("incomplete profile graph or missing confirmed receipt")
	}
	expected := []string{"listAllDevelopmentCerts", "listAppIds", "downloadTeamProvisioningProfile", "downloadTeamProvisioningProfile"}
	if !reflect.DeepEqual(r.requests, expected) {
		t.Fatalf("unexpected portal actions %v", r.requests)
	}
	if !receipt.Expires.Equal(r.profilesByRaw["profile-0"]["ExpirationDate"].(time.Time)) {
		t.Fatal("incorrect effective expiry")
	}
}
func TestProfileRefreshRequiresEveryReadbackAndUnchangedInventory(t *testing.T) {
	for _, kind := range []string{"missing profile", "changed installed app", "partial extension write"} {
		t.Run(kind, func(t *testing.T) {
			r := newRefreshRig(t, kind == "partial extension write")
			if kind == "missing profile" {
				r.omitReadback = true
			}
			if kind == "changed installed app" {
				r.changedOnReadback = true
			}
			if kind == "partial extension write" {
				r.errorOnInstall = errors.New("connection lost")
			}
			receipt, err := r.run(context.Background(), nil)
			if !errors.Is(err, errProfileRefreshUnconfirmed) || receipt != nil {
				t.Fatalf("unconfirmed operation claimed success: %+v %v", receipt, err)
			}
		})
	}
}
func TestProfileRefreshRecoversLostAcknowledgementByReadback(t *testing.T) {
	r := newRefreshRig(t, false)
	r.errorOnInstall = errors.New("connection lost after profile accepted")
	receipt, err := r.run(context.Background(), nil)
	if err != nil || receipt == nil {
		t.Fatalf("verified profile was not reconciled: %+v %v", receipt, err)
	}
}
func TestProfileRefreshValidatesWholeGraphBeforeFirstWrite(t *testing.T) {
	for _, kind := range []string{"revoked certificate", "different certificate", "wrong team", "wrong device", "lost capability", "shorter expiry", "invalid CMS"} {
		t.Run(kind, func(t *testing.T) {
			r := newRefreshRig(t, true)
			child := r.profilesByRaw["profile-1"]
			switch kind {
			case "revoked certificate":
				r.certRevoked = true
			case "different certificate":
				child["DeveloperCertificates"] = []any{[]byte("another certificate")}
			case "wrong team":
				child["TeamIdentifier"] = []any{"OTHERTEAM1"}
			case "wrong device":
				child["ProvisionedDevices"] = []any{"OTHER"}
			case "lost capability":
				delete(child["Entitlements"].(map[string]any), "keychain-access-groups")
			case "shorter expiry":
				child["ExpirationDate"] = r.binding.Members[1].Expires.Add(-time.Hour)
			case "invalid CMS":
				r.decodeErr = true
			}
			receipt, err := r.run(context.Background(), nil)
			if err == nil || receipt != nil || r.installs != 0 {
				t.Fatalf("incompatible graph was written: installs=%d receipt=%v err=%v", r.installs, receipt, err)
			}
		})
	}
}
func TestProfileRefreshDoesNotFabricateRenewalForUnchangedExpiry(t *testing.T) {
	r := newRefreshRig(t, false)
	r.profilesByRaw["profile-0"]["ExpirationDate"] = r.binding.Members[0].Expires
	receipt, err := r.run(context.Background(), nil)
	if err != nil || receipt != nil || r.installs != 0 {
		t.Fatal("unchanged profile advanced history")
	}
}
func TestProfileRefreshUsesConfirmedStoreReceiptAsNextBaseline(t *testing.T) {
	r := newRefreshRig(t, false)
	receipt, err := r.run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	r.installs = 0
	next, err := r.run(context.Background(), receipt)
	if err != nil || next != nil || r.installs != 0 {
		t.Fatal("already renewed profile was renewed or timestamped again")
	}
	// Losing that profile requires restoring it, rather than claiming it current.
	r.stored = nil
	next, err = r.run(context.Background(), receipt)
	if err != nil || next == nil || r.installs != 1 {
		t.Fatal("missing profile was not restored")
	}
}
func TestProfileRefreshDoesNotTurnAccountErrorsIntoReinstallRequests(t *testing.T) {
	r := newRefreshRig(t, false)
	r.requestErr = &apple.Error{Code: 1100, Message: "Session expired"}
	_, err := r.run(context.Background(), nil)
	if !errors.Is(err, r.requestErr) || errors.Is(err, errProfileRefreshUnsupported) || r.installs != 0 {
		t.Fatal("authentication failure changed refresh strategy")
	}
	r.requestErr = nil
	r.rejected = true
	r.errorOnInstall = errors.New("explicit device rejection")
	_, err = r.run(context.Background(), nil)
	if !errors.Is(err, errProfileRefreshUnsupported) {
		t.Fatal("explicit device rejection did not allow full signing fallback")
	}
}
func TestProfileRefreshCancellationDoesNotClaimSuccess(t *testing.T) {
	r := newRefreshRig(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	receipt, err := r.run(ctx, nil)
	if !errors.Is(err, context.Canceled) || receipt != nil || len(r.requests) != 0 || r.installs != 0 {
		t.Fatal("cancelled request touched portal/device")
	}
}
func TestProfileEntitlementAuthorizationPreservesSignedValues(t *testing.T) {
	if !profileAuthorizes([]any{"TEAM.*"}, []any{"TEAM.app", "TEAM.shared"}) {
		t.Fatal("authorized keychain groups rejected")
	}
	if profileAuthorizes([]any{"TEAM.app"}, []any{"TEAM.*"}) {
		t.Fatal("narrow profile authorized a wider signed group")
	}
	if !profileAuthorizes(true, false) || profileAuthorizes(false, true) {
		t.Fatal("debug authorization did not preserve reduced privileges")
	}
	if profileAuthorizes(map[string]any{}, map[string]any{"capability": true}) {
		t.Fatal("missing capability was accepted")
	}
}

func TestProfileRefreshFallbackOnlyForProvenIncompatibility(t *testing.T) {
	for _, tc := range []struct {
		name               string
		err                error
		canceled, fallback bool
	}{
		{name: "confirmed"},
		{name: "unsupported", err: fmt.Errorf("wrapped: %w", errProfileRefreshUnsupported), fallback: true},
		{name: "authentication", err: errors.New("sign in again")},
		{name: "lost connection", err: errors.New("connection reset")},
		{name: "unconfirmed writes", err: errProfileRefreshUnconfirmed},
		{name: "needs original", err: ErrRefreshNeedsIPA},
		{name: "canceled", err: errProfileRefreshUnsupported, canceled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			calls := 0
			got, err := profileFirstRefresh(ctx, func() (Result, error) { return Result{ProfileRefreshed: tc.err == nil}, tc.err }, func() (Result, error) { calls++; return Result{Installed: true}, nil })
			if (calls == 1) != tc.fallback || calls > 1 {
				t.Fatalf("fallback count %d", calls)
			}
			if tc.err == nil && (!got.ProfileRefreshed || got.Installed || err != nil) {
				t.Fatal("profile confirmation confused with installation")
			}
			if tc.canceled && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if tc.err != nil && !tc.fallback && !tc.canceled && !errors.Is(err, tc.err) {
				t.Fatalf("lost original error: %v", err)
			}
		})
	}
}

func TestProfileReceiptReconcilesOnlyCompleteUnchangedInstall(t *testing.T) {
	r := newRefreshRig(t, true)
	receipt, err := r.run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	items, _ := r.io().inventory(context.Background())
	old := r.binding.Members[0].Expires
	record := iosAppRecord{IOSApp: IOSApp{BundleID: r.binding.BundleID, Version: r.binding.Version, Build: r.binding.Build, Team: r.binding.Team, Expires: old}, ProfileExpires: old, Binding: r.binding, ProfileRefresh: receipt}
	profiles := []map[string]any{{"Entitlements": mapField(r.profilesByRaw[string(r.downloaded[0])], "Entitlements"), "ExpirationDate": old}}
	for i, hash := range receipt.Hashes {
		profiles = append(profiles, map[string]any{"_ipa_profile_hash": hash, "ExpirationDate": receipt.Expiries[i], "Entitlements": mapField(r.profilesByRaw[string(r.downloaded[i])], "Entitlements")})
	}
	records := map[string]iosAppRecord{record.BundleID: record}
	got := reconcileIOSApps(records, items, profiles)[record.BundleID]
	if !got.Expires.Equal(receipt.Expires) || !got.Refreshed.Equal(receipt.Refreshed) || got.Account != receipt.Account {
		t.Fatalf("confirmed receipt lost to old/new profile ambiguity: %+v", got)
	}
	got = reconcileIOSApps(records, items, profiles[:len(profiles)-1])[record.BundleID]
	if !got.Refreshed.IsZero() || got.Account != "" {
		t.Fatal("claimed complete refresh without extension profile")
	}
	items[0]["CFBundleVersion"] = "2"
	got = reconcileIOSApps(records, items, profiles)[record.BundleID]
	if !got.Refreshed.IsZero() || got.Account != "" {
		t.Fatal("receipt attributed to replaced app")
	}
}

func TestProfileRefreshDeadlineIncludesCertificateExpiry(t *testing.T) {
	r := newRefreshRig(t, false)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(r.binding.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	cert.NotAfter = time.Now().UTC().Truncate(time.Second).Add(48 * time.Hour)
	cert.PublicKey = &key.PublicKey
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	r.binding.Certificate = der
	for _, p := range r.profilesByRaw {
		p["DeveloperCertificates"] = []any{der}
	}
	receipt, err := r.run(context.Background(), nil)
	if err != nil || receipt == nil || !receipt.Expires.Equal(cert.NotAfter) {
		t.Fatalf("deadline must not exceed signing certificate: %+v %v", receipt, err)
	}
	r.installs = 0
	again, err := r.run(context.Background(), receipt)
	if err != nil || again != nil || r.installs != 0 {
		t.Fatalf("unchanged effective deadline repeated renewal: %+v %v", again, err)
	}
}

func TestProfileRefreshIgnoresUnrelatedAppIDDuplicates(t *testing.T) {
	r := newRefreshRig(t, true)
	r.extraAppIDs = []map[string]any{{"identifier": "org.example.unrelated", "appIdId": "A"}, {"identifier": "org.example.unrelated", "appIdId": "B"}, {"appIdId": "empty-A"}, {"appIdId": "empty-B"}}
	receipt, err := r.run(context.Background(), nil)
	if err != nil || receipt == nil || r.installs != 2 {
		t.Fatalf("unrelated portal records prevented refresh: %+v %v", receipt, err)
	}
}
func TestProfileRefreshRejectsOnlyConflictingTargetRegistrations(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		r := newRefreshRig(t, false)
		id := "ID-0"
		if conflict {
			id = "OTHER"
		}
		r.extraAppIDs = []map[string]any{{"identifier": r.binding.Members[0].Registration, "appIdId": id}}
		receipt, err := r.run(context.Background(), nil)
		if conflict {
			if !errors.Is(err, errProfileRefreshUnsupported) || r.installs != 0 {
				t.Fatal("conflicting registration did not prevent writes")
			}
		} else if err != nil || receipt == nil {
			t.Fatalf("identical registration duplicate prevented refresh: %v", err)
		}
	}
}

func TestProfileRefreshAcceptsProfileCreatedDuringDownload(t *testing.T) {
	r := newRefreshRig(t, true)
	r.createdDuringDownload = true
	receipt, err := r.run(context.Background(), nil)
	if err != nil || receipt == nil || r.installs != 2 {
		t.Fatalf("newly issued profile treated as future-dated: %+v %v", receipt, err)
	}
}
func TestProfileRefreshRejectsActuallyFutureDatedProfile(t *testing.T) {
	r := newRefreshRig(t, false)
	r.profilesByRaw[string(r.downloaded[0])]["CreationDate"] = time.Now().Add(time.Hour)
	_, err := r.run(context.Background(), nil)
	if !errors.Is(err, errProfileRefreshUnsupported) || r.installs != 0 {
		t.Fatal("future-dated profile accepted")
	}
}

func TestInstalledBindingResolvesExpiryDespiteOlderProfiles(t *testing.T) {
	r := newRefreshRig(t, true)
	earlier := r.binding.Members[0].Expires.Add(-12 * time.Hour)
	r.binding.Members[1].Expires = earlier
	original := r.binding.Members[0].Expires
	var profiles []map[string]any
	for i := range r.binding.Members {
		r.binding.Members[i].EmbeddedProfileHash = fmt.Sprintf("original-%d", i)
		profiles = append(profiles, map[string]any{"_ipa_profile_hash": r.binding.Members[i].EmbeddedProfileHash, "ExpirationDate": r.binding.Members[i].Expires, "Entitlements": mapField(r.profilesByRaw[string(r.downloaded[i])], "Entitlements")})
	}
	// Another retained profile authorizes the same main app with another expiry.
	profiles = append(profiles, map[string]any{"_ipa_profile_hash": "older-profile", "ExpirationDate": original.Add(-time.Hour), "Entitlements": mapField(r.profilesByRaw[string(r.downloaded[0])], "Entitlements")})
	items, _ := r.io().inventory(context.Background())
	if !inventoryAppExpiry(items[0], profiles).IsZero() {
		t.Fatal("test must retain genuinely ambiguous generic inventory")
	}
	record := iosAppRecord{IOSApp: IOSApp{BundleID: r.binding.BundleID, Version: r.binding.Version, Build: r.binding.Build, Account: "owner@example.invalid", Refreshed: time.Now()}, ProfileExpires: original, Binding: r.binding}
	records := map[string]iosAppRecord{record.BundleID: record}
	got := reconcileIOSApps(records, items, profiles)[record.BundleID]
	if !got.Expires.Equal(earlier) || got.Account != record.Account || !got.Refreshed.Equal(record.Refreshed) {
		t.Fatalf("lost confirmed installation proof: %+v", got)
	}
	// A successful already-current check can recover a missing account without
	// claiming that it renewed profiles or overwriting known install history.
	record.CheckedAccount = "checked@example.invalid"
	records[record.BundleID] = record
	if got = reconcileIOSApps(records, items, profiles)[record.BundleID]; got.Account != record.Account {
		t.Fatal("verification overwrote recorded install account")
	}
	record.Account, record.Refreshed = "", time.Time{}
	records[record.BundleID] = record
	got = reconcileIOSApps(records, items, profiles)[record.BundleID]
	if got.Account != record.CheckedAccount || !got.Refreshed.IsZero() {
		t.Fatal("verified account missing or invented a renewal timestamp")
	}
	// Incomplete graph proof or a replaced app must still leave dates unknown.
	missingExtension := []map[string]any{profiles[0], profiles[2]}
	got = reconcileIOSApps(records, items, missingExtension)[record.BundleID]
	if !got.Expires.IsZero() || got.Account != "" {
		t.Fatal("incomplete graph supplied an exact expiry or verified account")
	}
	items[0]["CFBundleVersion"] = "replaced"
	got = reconcileIOSApps(records, items, profiles)[record.BundleID]
	if !got.Refreshed.IsZero() || got.Account != "" {
		t.Fatal("old refresh or verified account attributed to replacement")
	}
}
