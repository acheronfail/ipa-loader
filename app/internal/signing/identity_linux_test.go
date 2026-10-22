//go:build linux

package signing

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// This helper emulates only Secret Service persistence, never encryption or a
// real desktop keyring. The production backend is separately checked to fail
// closed when the service is unavailable.
func syntheticKeyring(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	script := `#!/bin/sh
for key do :; done
case "$1" in
store) umask 077; cat > "$TEST_KEYRING/$key";;
lookup) if test -f "$TEST_KEYRING/$key"; then cat "$TEST_KEYRING/$key"; else exit 1; fi;;
*) exit 2;;
esac
`
	if err := os.WriteFile(filepath.Join(root, "secret-tool"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_KEYRING", root)
	t.Setenv("PATH", root+":"+os.Getenv("PATH"))
}
func TestLinuxIdentityRetainsSubmissionAndActivatesMatchingCertificate(t *testing.T) {
	syntheticKeyring(t)
	const team = "TESTTEAM10"
	vault := IdentityVault{Dir: filepath.Join(t.TempDir(), "signing")}
	first, err := vault.Prepare(team)
	if err != nil || !first.Created || !first.NeedsSubmission {
		t.Fatal("fresh CSR failed", err)
	}
	if err = vault.MarkSubmitted(team, first.RequestID); err != nil {
		t.Fatal(err)
	}
	second, err := (IdentityVault{Dir: vault.Dir}).Prepare(team)
	if err != nil || second.Created || second.NeedsSubmission || second.CSR != first.CSR {
		t.Fatal("uncertain CSR changed or became retryable", err)
	}
	if err = vault.MarkQuotaRejected(team, first.RequestID, 503); err == nil {
		t.Fatal("ambiguous failure permitted resubmission")
	}
	if err = vault.MarkQuotaRejected(team, first.RequestID, 7460); err != nil {
		t.Fatal(err)
	}
	retry, err := vault.Prepare(team)
	if err != nil || !retry.NeedsSubmission || retry.CSR != first.CSR {
		t.Fatal("quota retry changed key", err)
	}
	block, _ := pem.Decode([]byte(first.CSR))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{OrganizationalUnit: []string{team}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(72 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, csr.PublicKey, issuer)
	if err != nil {
		t.Fatal(err)
	}
	if err = vault.SaveCertificate(team, der); err != nil {
		t.Fatal(err)
	}
	identity, err := (IdentityVault{Dir: vault.Dir}).Load(team)
	if err != nil || !bytes.Equal(identity.Certificate.Raw, der) {
		t.Fatal("certificate activation failed", err)
	}
	entries, err := os.ReadDir(vault.Dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".lock" {
			t.Fatal("signing key leaked to filesystem", entry.Name())
		}
	}
	unlock, err := vault.locked(team)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if other, err := vault.locked(team); err == nil {
		other()
		t.Fatal("concurrent signing identity operation permitted")
	}
}
