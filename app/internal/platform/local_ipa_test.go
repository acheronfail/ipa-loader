//go:build darwin || linux || windows

package platform

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"howett.net/plist"
	"ipa-loader/app/internal/apple"
	"ipa-loader/app/internal/ipa"
	"ipa-loader/app/internal/signing"
)

// Optional local integration check. Profiles and signer are synthetic: this
// exercises preparation, signing and packaging, without portal or device access.
func TestLocalIPACompatibility(t *testing.T) {
	input := os.Getenv("IPA_LOADER_TEST_IPA")
	if input == "" {
		t.Skip("set IPA_LOADER_TEST_IPA to test a local IPA")
	}
	for _, local := range []bool{false, true} {
		t.Run(map[bool]string{false: "paid", true: "free"}[local], func(t *testing.T) {
			testLocalIPACompatibility(t, input, local, nil)
		})
	}
}

func TestLocalIPAWithoutExtensions(t *testing.T) {
	input := os.Getenv("IPA_LOADER_TEST_IPA")
	if input == "" {
		t.Skip("set IPA_LOADER_TEST_IPA to test a local IPA")
	}
	for _, local := range []bool{false, true} {
		t.Run(map[bool]string{false: "paid", true: "free"}[local], func(t *testing.T) {
			testLocalIPACompatibility(t, input, local, &ipa.ExtensionSelection{Included: []string{}})
		})
	}
}

func testLocalIPACompatibility(t *testing.T, input string, local bool, selection *ipa.ExtensionSelection) {
	hash := func() [32]byte {
		f, err := os.Open(input)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		h := sha256.New()
		if _, err = io.Copy(h, f); err != nil {
			t.Fatal(err)
		}
		var sum [32]byte
		copy(sum[:], h.Sum(nil))
		return sum
	}
	before := hash()
	work := t.TempDir()
	ctx := WithExtensionSelection(context.Background(), selection)
	app, err := extractIPA(ctx, input, work)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s %s: %d embedded code objects", app.BundleID, app.Version, len(app.Embedded))
	const team = "ABCDEFGHIJ"
	ids, err := standardBundleIdentity(app.BundleID, team)
	if err != nil {
		t.Fatal(err)
	}
	if !local {
		ids.Installed = ids.Original
	}
	e := newControllerTestEngine(ctx, work)
	e.message = func(s string) { t.Log(s) }
	sharing, err := e.preflightSharing(app, team, ids)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Local IPA synthetic signer", OrganizationalUnit: []string{team}}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, IsCA: true, BasicConstraintsValid: true}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	var groups []string
	if sharing != nil {
		requests := []sharingRequest{app.Sharing}
		for _, object := range app.Embedded {
			if object.Extension {
				requests = append(requests, object.Sharing)
			}
		}
		for _, request := range requests {
			for _, group := range request.AppGroups {
				mapped := group + "." + team
				if !contains(groups, mapped) {
					groups = append(groups, mapped)
				}
			}
		}
	}
	profile := func(registration string) map[string]any {
		p := extensionProfileFixture(registration, local, now)
		p["TeamIdentifier"] = []any{team}
		p["ApplicationIdentifierPrefix"] = []any{team}
		p["DeveloperCertificates"] = []any{cert}
		ent := mapField(p, "Entitlements")
		ent["application-identifier"] = team + "." + registration
		ent["com.apple.developer.team-identifier"] = team
		ent["keychain-access-groups"] = []any{team + ".*"}
		if local {
			ent["keychain-access-groups"] = []any{team + "." + registration}
		} else {
			ent["com.apple.security.application-groups"] = groups
		}
		return p
	}
	p := profile(ids.Registration)
	ent, err := validateResolvedProfile(p, fingerprint(cert), team, ids, "PHONE", now)
	if err != nil {
		t.Fatal(err)
	}
	e.applyCapabilities(app.Path, p, ent, app.Capabilities, map[string]string{ids.Original: ids.Installed})
	if err = app.applyBundleIdentity(ids); err != nil {
		t.Fatal(err)
	}
	var registration string
	client := portalFunc(func(_ context.Context, _ *apple.Session, action string, params map[string]any, _ string) (map[string]any, error) {
		switch action {
		case "listAppIds":
			return map[string]any{"appIds": []any{}}, nil
		case "addAppId":
			registration = stringField(params, "identifier")
			return map[string]any{"appId": map[string]any{"appIdId": "CHILD", "enabledFeatures": []any{"APG3427HIY"}, "features": map[string]any{"APG3427HIY": true}}}, nil
		case "listApplicationGroups":
			if local {
				t.Fatal("free account attempted app-group provisioning")
			}
			var records []any
			for _, g := range groups {
				records = append(records, map[string]any{"identifier": g, "applicationGroup": "GROUP"})
			}
			return map[string]any{"applicationGroupList": records}, nil
		case "assignApplicationGroupToAppId":
			return map[string]any{}, nil
		case "downloadTeamProvisioningProfile":
			raw, _ := plist.Marshal(profile(registration), plist.XMLFormat)
			return map[string]any{"provisioningProfile": map[string]any{"encodedProfile": raw}}, nil
		default:
			t.Fatalf("unexpected portal action %s", action)
			return nil, nil
		}
	})
	e.decodeProfile = os.ReadFile
	if sharing != nil {
		preliminary, err := planSharing(app.Sharing, team, team, ids.Registration, sharing.Registrations)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = e.provisionAppProfile(client, &apple.Session{}, team, ids.Registration, preliminary.AppGroups...); err != nil {
			t.Fatal(err)
		}
	}
	if err = e.prepareExtensions(&app, client, &apple.Session{}, fingerprint(cert), team, "PHONE", ids, p, sharing); err != nil {
		t.Fatal(err)
	}
	plan, err := sharingFor(app.Sharing, team, ids.Registration, p, sharing)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.applySharing(app.Path, filepath.Join(app.Path, app.Executable), p, ent, plan, sharing); err != nil {
		t.Fatal(err)
	}
	if err = refreshSigningGraph(e, &app); err != nil {
		t.Fatal(err)
	}
	raw, _ := plist.Marshal(p, plist.XMLFormat)
	profilePath := filepath.Join(app.Path, "embedded.mobileprovision")
	if err = os.WriteFile(profilePath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	raw, _ = plist.Marshal(ent, plist.XMLFormat)
	entPath := filepath.Join(work, "entitlements.plist")
	if err = os.WriteFile(entPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	defer clear(keyPEM)
	tool := signing.Tool{Profile: profilePath}
	for _, o := range app.Embedded {
		tool.Identifier = o.Identifier
		if err = tool.Sign(ctx, o.Path, keyPEM, cert, o.Entitlements); err != nil {
			t.Fatalf("sign %s: %v", filepath.Base(o.Path), err)
		}
	}
	tool.Identifier = app.BundleID
	if err = tool.Sign(ctx, app.Path, keyPEM, cert, entPath); err != nil {
		t.Fatal(err)
	}
	archive, err := packageSignedApp(ctx, app.Path, work)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := extractIPA(ctx, archive, t.TempDir())
	if err != nil {
		t.Fatal("prepared IPA cannot be re-imported: ", err)
	}
	if len(reloaded.Embedded) != len(app.Embedded) {
		t.Fatal("packaging changed the signing graph")
	}
	if local && sharing != nil && !reflect.DeepEqual(reloaded.Sharing.AppGroups, app.Sharing.AppGroups) {
		t.Fatal("free app-local group requests did not survive packaging")
	}
	if hash() != before {
		t.Fatal("source IPA changed")
	}
	t.Logf("Prepared, signed, verified and packaged %d embedded code objects", len(app.Embedded))
}
