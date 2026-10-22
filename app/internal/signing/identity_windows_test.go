//go:build windows

package signing

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ipa-loader/app/internal/securestore"
)

func issueCertificate(t *testing.T, pub *rsa.PublicKey, team string) []byte {
	return issueCertificateDates(t, pub, team, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}

func issueCertificateDates(t *testing.T, pub *rsa.PublicKey, team string, before, after time.Time) []byte {
	t.Helper()
	issuer, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic Development", OrganizationalUnit: []string{team}}, NotBefore: before, NotAfter: after}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, issuer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestWindowsIdentitySubmissionStateSurvivesRestart(t *testing.T) {
	vault := IdentityVault{Dir: filepath.Join(t.TempDir(), "identities")}
	const team = "TESTTEAM10"
	first, err := vault.Prepare(team)
	if err != nil || !first.Created || !first.NeedsSubmission {
		t.Fatal("fresh request was not ready", err)
	}
	retry, err := vault.Prepare(team)
	if err != nil || retry.Created || !retry.NeedsSubmission || retry.CSR != first.CSR || retry.RequestID != first.RequestID {
		t.Fatal("never-submitted retained request was not reusable", err)
	}
	if err = vault.MarkSubmitted(team, "different request"); err == nil {
		t.Fatal("changed request marked submitted")
	}
	if err = vault.MarkSubmitted(team, first.RequestID); err != nil {
		t.Fatal(err)
	}
	retry, err = (IdentityVault{Dir: vault.Dir}).Prepare(team)
	if err != nil || retry.Created || retry.NeedsSubmission || retry.CSR != first.CSR {
		t.Fatal("uncertain submission regenerated or became resendable", err)
	}
	if err = vault.MarkSubmitted(team, first.RequestID); err == nil {
		t.Fatal("already submitted request permitted a resend")
	}
	// A pre-field record is uncertain, even though no certificate is saved.
	record, _, err := vault.read(team)
	if err != nil {
		t.Fatal(err)
	}
	record.Submitted = nil
	if err = vault.write(record); err != nil {
		t.Fatal(err)
	}
	retry, err = vault.Prepare(team)
	if err != nil || retry.NeedsSubmission || retry.Created || retry.CSR != first.CSR {
		t.Fatal("legacy request was interpreted as never submitted", err)
	}
}

func TestWindowsQuotaRejectionRetainsSameRequest(t *testing.T) {
	vault := IdentityVault{Dir: filepath.Join(t.TempDir(), "identities")}
	const team = "TESTTEAM10"
	pending, err := vault.Prepare(team)
	if err != nil {
		t.Fatal(err)
	}
	if err = vault.MarkSubmitted(team, pending.RequestID); err != nil {
		t.Fatal(err)
	}
	for _, code := range []int{0, 503, 1100} {
		if vault.MarkQuotaRejected(team, pending.RequestID, code) == nil {
			t.Fatal("uncertain failure became retryable")
		}
	}
	if vault.MarkQuotaRejected(team, "changed", 7460) == nil {
		t.Fatal("changed request accepted")
	}
	if err = vault.MarkQuotaRejected(team, pending.RequestID, 7460); err != nil {
		t.Fatal(err)
	}
	retry, err := (IdentityVault{Dir: vault.Dir}).Prepare(team)
	if err != nil || !retry.NeedsSubmission || retry.Created || retry.CSR != pending.CSR || retry.RequestID != pending.RequestID {
		t.Fatal("rejected request was not safely retained", err)
	}
	if vault.MarkQuotaRejected(team, pending.RequestID, 7460) == nil {
		t.Fatal("unsubmitted request marked rejected")
	}
}

func TestWindowsExpiredCompletedIdentityArchivesBeforeRenewal(t *testing.T) {
	testWindowsCompletedIdentityRenewal(t, -time.Hour)
}

func TestWindowsNearExpiryCompletedIdentityArchivesBeforeRenewal(t *testing.T) {
	testWindowsCompletedIdentityRenewal(t, 12*time.Hour)
}

func testWindowsCompletedIdentityRenewal(t *testing.T, remaining time.Duration) {
	t.Helper()
	vault := IdentityVault{Dir: filepath.Join(t.TempDir(), "identities")}
	const team = "TESTTEAM10"
	first, err := vault.Prepare(team)
	if err != nil {
		t.Fatal(err)
	}
	record, key, err := vault.read(team)
	if err != nil {
		t.Fatal(err)
	}
	expired := issueCertificateDates(t, &key.PublicKey, team, time.Now().Add(-48*time.Hour), time.Now().Add(remaining))
	record.Certificate = expired
	submitted := true
	record.Submitted = &submitted
	if err = vault.write(record); err != nil {
		t.Fatal(err)
	}
	renewed, err := vault.Prepare(team)
	if err != nil || !renewed.Created || !renewed.NeedsSubmission || renewed.CSR == first.CSR || renewed.RequestID == first.RequestID {
		t.Fatal("expired completed identity was not renewed once", err)
	}
	entries, err := os.ReadDir(filepath.Join(vault.Dir, "history"))
	if err != nil || len(entries) != 1 {
		t.Fatal("completed identity archive missing", err)
	}
	plain, err := securestore.Read(filepath.Join(vault.Dir, "history", entries[0].Name()), 65536)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	var archived identityRecord
	if json.Unmarshal(plain, &archived) != nil || !bytes.Equal(archived.Certificate, expired) || !bytes.Equal(archived.PrivateKey, record.PrivateKey) || archived.RequestID != first.RequestID {
		t.Fatal("archive did not preserve completed certificate and private key")
	}
	retry, err := vault.Prepare(team)
	if err != nil || retry.Created || retry.CSR != renewed.CSR || !retry.NeedsSubmission {
		t.Fatal("renewal created multiple pending keys", err)
	}
	if _, err = vault.Load(team); err != ErrNoIdentity {
		t.Fatal("new pending key treated as activated identity", err)
	}
}

func TestWindowsIdentityRenewalMarginBoundary(t *testing.T) {
	now := time.Unix(1800000000, 0)
	for _, test := range []struct {
		remaining time.Duration
		want      bool
	}{{-time.Second, true}, {0, true}, {24*time.Hour - time.Nanosecond, true}, {24 * time.Hour, false}, {24*time.Hour + time.Nanosecond, false}} {
		if actual := needsIdentityRenewal(&x509.Certificate{NotAfter: now.Add(test.remaining)}, now); actual != test.want {
			t.Fatal("completed certificate renewal does not match selection margin")
		}
	}
}

func TestWindowsMalformedCompletedIdentityNeverRenews(t *testing.T) {
	vault := IdentityVault{Dir: filepath.Join(t.TempDir(), "identities")}
	const team = "TESTTEAM10"
	if _, err := vault.Prepare(team); err != nil {
		t.Fatal(err)
	}
	record, _, err := vault.read(team)
	if err != nil {
		t.Fatal(err)
	}
	record.Certificate = []byte("malformed completed certificate")
	if err = vault.write(record); err != nil {
		t.Fatal(err)
	}
	path, _ := vault.path(team)
	before, _ := os.ReadFile(path)
	if _, err = vault.Prepare(team); err == nil {
		t.Fatal("malformed certificate regenerated identity")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("malformed completed identity was overwritten")
	}
}

func TestWindowsIdentityArchiveFailurePreservesCompletedRecord(t *testing.T) {
	vault := IdentityVault{Dir: filepath.Join(t.TempDir(), "identities")}
	const team = "TESTTEAM10"
	if _, err := vault.Prepare(team); err != nil {
		t.Fatal(err)
	}
	record, key, err := vault.read(team)
	if err != nil {
		t.Fatal(err)
	}
	record.Certificate = issueCertificateDates(t, &key.PublicKey, team, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	if err = vault.write(record); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(vault.Dir, "history"), []byte("conflicting history path"), 0600); err != nil {
		t.Fatal(err)
	}
	path, _ := vault.path(team)
	before, _ := os.ReadFile(path)
	if _, err = vault.Prepare(team); err == nil {
		t.Fatal("renewed identity without retaining completed history")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("archive failure overwrote completed identity")
	}
}

func TestWindowsIdentityRecoveryAndActivation(t *testing.T) {
	vault := IdentityVault{Dir: filepath.Join(t.TempDir(), "identities")}
	const team = "TESTTEAM10"
	first, err := vault.Prepare(team)
	if err != nil || !first.Created {
		t.Fatal("could not prepare a new retained identity", err)
	}
	second, err := (IdentityVault{Dir: vault.Dir}).Prepare(team)
	if err != nil || second.Created || second.CSR != first.CSR || second.RequestID != first.RequestID {
		t.Fatal("restart generated another CSR or key", err)
	}
	if _, err = vault.Load(team); err != ErrNoIdentity {
		t.Fatal("pending key treated as an active identity", err)
	}
	block, _ := pem.Decode([]byte(first.CSR))
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || request.CheckSignature() != nil {
		t.Fatal("invalid retained CSR", err)
	}
	pub := request.PublicKey.(*rsa.PublicKey)
	wrong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if err = vault.SaveCertificate(team, issueCertificate(t, &wrong.PublicKey, team)); err == nil {
		t.Fatal("unrelated certificate activated")
	}
	if err = vault.SaveCertificate(team, issueCertificate(t, pub, "OTHERTEAM1")); err == nil {
		t.Fatal("cross-team certificate activated")
	}
	der := issueCertificate(t, pub, team)
	if err = vault.SaveCertificate(team, der); err != nil {
		t.Fatal("matching certificate was not activated", err)
	}
	identity, err := vault.Load(team)
	if err != nil || identity.Team != team || !bytes.Equal(identity.Certificate.Raw, der) || identity.PrivateKey.PublicKey.N.Cmp(pub.N) != 0 {
		t.Fatal("activated identity did not round trip", err)
	}
	path, _ := vault.path(team)
	sealed, err := os.ReadFile(path)
	if err != nil || bytes.Contains(sealed, []byte("PRIVATE KEY")) || bytes.Contains(sealed, identity.PrivateKey.D.Bytes()) {
		t.Fatal("durable identity contained plaintext signing material", err)
	}
	sealed[len(sealed)-1] ^= 0xff
	if err = os.WriteFile(path, sealed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = vault.Prepare(team); err == nil {
		t.Fatal("corrupt key generated a replacement CSR")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(sealed, after) {
		t.Fatal("corrupt recovery material was overwritten")
	}
}
