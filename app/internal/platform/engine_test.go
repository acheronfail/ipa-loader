package platform

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"ipa-loader/app/internal/apple"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakePortal struct {
	t       *testing.T
	cert    []byte
	actions []string
	issue   bool
	issuer  *rsa.PrivateKey
}

type portalFunc func(context.Context, *apple.Session, string, map[string]any, string) (map[string]any, error)

func (f portalFunc) Request(ctx context.Context, s *apple.Session, action string, p map[string]any, team string) (map[string]any, error) {
	return f(ctx, s, action, p, team)
}

func TestStandardIdentifierProvisioning(t *testing.T) {
	for _, mode := range []string{"create", "reuse", "conflict", "limit", "timeout", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			key, _ := rsa.GenerateKey(rand.Reader, 2048)
			portal := &fakePortal{t: t, cert: testCertificate(t, key, time.Now().Add(48*time.Hour), 1)}
			e, _ := fakeEngine(t, portal, true)
			ids, err := standardBundleIdentity("org.example.fixture", "TEAM")
			if err != nil {
				t.Fatal(err)
			}
			adds, downloads := 0, 0
			client := portalFunc(func(ctx context.Context, session *apple.Session, action string, params map[string]any, team string) (map[string]any, error) {
				switch action {
				case "listAppIds":
					apps := []any{map[string]any{"identifier": ids.Original, "appIdId": "OLD"}}
					if mode == "reuse" {
						apps = append(apps, map[string]any{"identifier": ids.Registration, "appIdId": "APP"})
					}
					return map[string]any{"appIds": apps}, nil
				case "addAppId":
					adds++
					if params["identifier"] != "org.example.fixture.TEAM" {
						t.Fatal("registration did not use literal team suffix up front")
					}
					switch mode {
					case "conflict":
						return nil, &apple.Error{Code: 9401}
					case "limit":
						return nil, &apple.Error{Code: 9120}
					case "invalid":
						return nil, &apple.Error{Code: 9412}
					case "timeout":
						return nil, context.DeadlineExceeded
					}
					return map[string]any{"appId": map[string]any{"appIdId": "APP"}}, nil
				case "downloadTeamProvisioningProfile":
					downloads++
				}
				return portal.Request(ctx, session, action, params, team)
			})
			_, _, err = e.provision(client, &apple.Session{}, "TEAM", "PHONE", ids.Registration)
			if mode == "create" || mode == "reuse" {
				if err != nil || downloads != 1 {
					t.Fatal("profile lookup failed")
				}
				if mode == "reuse" && adds != 0 {
					t.Fatal("registration was not reused")
				}
			} else if err == nil || adds != 1 || downloads != 0 {
				t.Fatal("portal error triggered an extra registration or profile download")
			}
		})
	}
}

func (f *fakePortal) Request(_ context.Context, _ *apple.Session, action string, p map[string]any, team string) (map[string]any, error) {
	f.actions = append(f.actions, action)
	if team != "TEAM" {
		f.t.Fatal("wrong team")
	}
	if strings.Contains(strings.ToLower(action), "revoke") || strings.Contains(strings.ToLower(action), "delete") {
		f.t.Fatal("destructive portal action")
	}
	switch action {
	case "listAllDevelopmentCerts":
		a := []any{}
		if len(f.cert) > 0 {
			a = append(a, map[string]any{"certContent": f.cert})
		}
		return map[string]any{"certificates": a}, nil
	case "listDevices":
		return map[string]any{"devices": []any{map[string]any{"deviceNumber": "PHONE"}}}, nil
	case "listAppIds":
		return map[string]any{"appIds": []any{map[string]any{"identifier": "org.example.fixture", "appIdId": "APP"}}}, nil
	case "downloadTeamProvisioningProfile":
		if p["appIdId"] != "APP" {
			f.t.Fatal("wrong app profile")
		}
		return map[string]any{"provisioningProfile": map[string]any{"encodedProfile": []byte("synthetic CMS")}}, nil
	case "submitDevelopmentCSR":
		if !f.issue {
			f.t.Fatal("unexpected duplicate CSR")
		}
		block, _ := pem.Decode([]byte(p["csrContent"].(string)))
		csr, e := x509.ParseCertificateRequest(block.Bytes)
		if e != nil || csr.CheckSignature() != nil {
			f.t.Fatal("CSR signature invalid")
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "Synthetic issued certificate"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}
		f.cert, e = x509.CreateCertificate(rand.Reader, tmpl, tmpl, csr.PublicKey, f.issuer)
		if e != nil {
			f.t.Fatal(e)
		}
		return map[string]any{}, nil
	}
	f.t.Fatal("unexpected portal action " + action)
	return nil, nil
}
func fakeEngine(t *testing.T, portal *fakePortal, hasIdentity bool, configRoot ...string) (*engine, *[]string) {
	t.Helper()
	e := newControllerTestEngine(context.Background(), t.TempDir())
	config := testConfigDir(t)
	if len(configRoot) > 0 {
		config = configRoot[0]
	}
	e.configDir = func() (string, error) { return config, nil }
	calls := []string{}
	e.host.(*controllerTestHost).identity = func() (map[string]bool, error) {
		calls = append(calls, "load identity")
		return map[string]bool{fingerprint(portal.cert): hasIdentity}, nil
	}
	return e, &calls
}

func testConfigDir(t *testing.T) string {
	t.Helper()
	home, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	return home
}
func TestProvisionReusesStoredIdentityWithoutCSR(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	p := &fakePortal{t: t, cert: testCertificate(t, key, time.Now().Add(48*time.Hour), 1)}
	e, commands := fakeEngine(t, p, true)
	identity, profile, err := e.provision(p, &apple.Session{}, "TEAM", "PHONE", "org.example.fixture")
	if err != nil {
		t.Fatal(err)
	}
	if identity != fingerprint(p.cert) || string(profile) != "synthetic CMS" {
		t.Fatal("wrong provisioning result")
	}
	if len(*commands) != 1 || (*commands)[0] != "load identity" {
		t.Fatal("existing private key was exported or modified")
	}
	if strings.Join(p.actions, ",") != "listAllDevelopmentCerts,listDevices,listAppIds,downloadTeamProvisioningProfile" {
		t.Fatal(p.actions)
	}
}
func TestCommandFailureAndCancellationDoNotExposeDiagnostics(t *testing.T) {
	e := newControllerTestEngine(context.Background(), t.TempDir())
	e.run = func(string, ...string) ([]byte, []byte, error) {
		return []byte("secret stdout"), []byte("secret stderr"), errors.New("secret failure")
	}
	_, err := e.command("stage", "unused")
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("diagnostic leaked")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.ctx = ctx
	e.run = func(string, ...string) ([]byte, []byte, error) {
		t.Fatal("cancelled command executed")
		return nil, nil, nil
	}
	if _, err = e.command("stage", "unused"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
}
func TestMalformedEntitlementTypesRejectWithoutPanic(t *testing.T) {
	for i := 0; i < 20; i++ {
		if basicEntitlements(map[string]any{"application-identifier": map[string]any{}, "keychain-access-groups": []any{map[string]any{}}}) == nil {
			t.Fatal("malformed entitlement accepted")
		}
	}
}
