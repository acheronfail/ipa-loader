package platform

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"github.com/smallstep/pkcs7"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Exercise the real crypto boundary separately from the controller's portal mocks.
func TestGoProfileVerification(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(testCertificate(t, key, time.Now().Add(time.Hour), 77))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("synthetic authenticated provisioning content")
	signed, err := pkcs7.NewSignedData(payload)
	if err != nil {
		t.Fatal(err)
	}
	signed.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err = signed.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	envelope, err := signed.Finish()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "profile.mobileprovision")
	if err = os.WriteFile(path, envelope, 0600); err != nil {
		t.Fatal(err)
	}
	actual, err := decodeProfile(path)
	if err != nil || !bytes.Equal(actual, payload) {
		t.Fatal("Go profile verification failed", err)
	}
	changed := bytes.Replace(envelope, payload, bytes.Repeat([]byte{'x'}, len(payload)), 1)
	if bytes.Equal(changed, envelope) {
		t.Fatal("fixture content not found")
	}
	if err = os.WriteFile(path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = decodeProfile(path); err == nil {
		t.Fatal("accepted modified profile content")
	}
}
