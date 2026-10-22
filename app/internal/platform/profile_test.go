package platform

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func testCertificate(t *testing.T, key *rsa.PrivateKey, expiry time.Time, serial int64) []byte {
	t.Helper()
	c := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Synthetic fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature}
	b, e := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestCertificateMatchingAndLifetimes(t *testing.T) {
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	short := testCertificate(t, key, now.Add(time.Hour), 1)
	long := testCertificate(t, key, now.Add(48*time.Hour), 2)
	records := []map[string]any{{"certContent": short}, {"certContent": long}, {"certContent": []byte("bad")}}
	identities := map[string]bool{fingerprint(short): true, fingerprint(long): true}
	selected := chooseCertificate(records, identities, now)
	if selected == nil || fingerprint(selected["certContent"].([]byte)) != fingerprint(long) {
		t.Fatal("valid local certificate not selected")
	}
	if chooseCertificate(records, map[string]bool{}, now) != nil {
		t.Fatal("remote certificate without local private key selected")
	}
	records[1]["revoked"] = true
	if chooseCertificate(records, identities, now) != nil {
		t.Fatal("revoked/short-lived certificate accepted")
	}
}
func TestProfileBindsTeamCertificateDeviceAndBundle(t *testing.T) {
	now := time.Now()
	cert := []byte("synthetic certificate bytes")
	p := map[string]any{"Platform": []any{"iOS"}, "ExpirationDate": now.Add(time.Hour), "TeamIdentifier": []any{"TEAM"}, "ApplicationIdentifierPrefix": []any{"PREFIX"}, "DeveloperCertificates": []any{cert}, "ProvisionedDevices": []any{"PHONE"}, "Entitlements": map[string]any{"application-identifier": "PREFIX.org.example.*", "com.apple.developer.team-identifier": "TEAM", "keychain-access-groups": []any{"PREFIX.*"}, "get-task-allow": true}}
	fp := fingerprint(cert)
	ent, e := validateProfile(p, fp, "TEAM", "org.example.fixture", "PHONE", now)
	if e != nil {
		t.Fatal(e)
	}
	if ent["application-identifier"] != "PREFIX.org.example.fixture" {
		t.Fatal("incorrect entitlement derivation")
	}
	for _, args := range [][4]string{{"BAD", "TEAM", "org.example.fixture", "PHONE"}, {fp, "OTHER", "org.example.fixture", "PHONE"}, {fp, "TEAM", "org.other.fixture", "PHONE"}, {fp, "TEAM", "org.example.fixture", "OTHERPHONE"}} {
		if _, e := validateProfile(p, args[0], args[1], args[2], args[3], now); e == nil {
			t.Fatal("mismatched authorization accepted")
		}
	}
	p["ExpirationDate"] = now.Add(-time.Second)
	if _, e := validateProfile(p, fp, "TEAM", "org.example.fixture", "PHONE", now); e == nil {
		t.Fatal("expired profile accepted")
	}
}
