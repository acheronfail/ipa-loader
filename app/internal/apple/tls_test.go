package apple

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"testing"
)

func TestAppleRootIsPublishedSelfSignedCA(t *testing.T) {
	sum := sha256.Sum256(appleRootDER)
	if hex.EncodeToString(sum[:]) != "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024" {
		t.Fatal("Apple root certificate changed")
	}
	root, err := x509.ParseCertificate(appleRootDER)
	// This legacy trust anchor has a SHA-1 self-signature. Its exact published
	// DER fingerprint establishes identity; leaf/intermediate signatures still
	// undergo ordinary TLS chain verification.
	if err != nil || !root.IsCA || !bytes.Equal(root.RawSubject, root.RawIssuer) || root.Subject.CommonName != "Apple Root CA" {
		t.Fatal("invalid Apple trust anchor")
	}
	transport := appleTransport().(*scopedAppleTransport)
	if transport.ordinary.TLSClientConfig != nil && transport.ordinary.TLSClientConfig.RootCAs != nil {
		t.Fatal("extra Apple trust leaked to ordinary transport")
	}
	if transport.gsa.TLSClientConfig.InsecureSkipVerify || transport.gsa.TLSClientConfig.RootCAs == nil {
		t.Fatal("GSA certificate verification disabled")
	}
}

func TestVerifiedAppleEndpoint(t *testing.T) {
	if os.Getenv("IPA_LOADER_TEST_APPLE_HTTPS") != "1" {
		t.Skip("explicit credential-free Apple TLS probe")
	}
	client := New(nil)
	response, err := client.HTTPClient.Get(gsaURL)
	if err != nil {
		t.Fatal("verified GSA TLS request failed")
	}
	defer response.Body.Close()
	if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		t.Fatal("GSA chain was not verified")
	}
}
