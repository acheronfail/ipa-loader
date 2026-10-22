package codesignverify

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestSyntheticCMSBoundary(t *testing.T) {
	openssl := os.Getenv("IPA_LOADER_TEST_OPENSSL")
	if !filepath.IsAbs(openssl) {
		t.Skip("explicit native OpenSSL path required for synthetic CMS checks")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "IPA Loader Synthetic Verifier Test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	certPath, keyPath, contentPath, cmsPath := filepath.Join(work, "cert.pem"), filepath.Join(work, "key.pem"), filepath.Join(work, "content.bin"), filepath.Join(work, "cms.der")
	primary := make([]byte, 44)
	primary[37] = 2
	for path, body := range map[string][]byte{certPath: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), keyPath: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), contentPath: primary} {
		if err = os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command(openssl, "cms", "-sign", "-binary", "-in", contentPath, "-signer", certPath, "-inkey", keyPath, "-md", "sha256", "-outform", "DER", "-out", cmsPath, "-nosmimecap")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("synthetic CMS creation failed: %v %s", err, out)
	}
	cms, err := os.ReadFile(cmsPath)
	if err != nil {
		t.Fatal(err)
	}
	v := &verifier{ctx: context.Background(), options: Options{CertificateDER: cert}}
	if err = v.cms(cms, [][]byte{primary}); err != nil {
		t.Fatal(err)
	}
	wrong := append([]byte{}, primary...)
	wrong[0] ^= 1
	if err = v.cms(cms, [][]byte{wrong}); err == nil {
		t.Fatal("CMS accepted changed signed content")
	}
	v.options.CertificateDER = []byte("different certificate")
	if err = v.cms(cms, [][]byte{primary}); err == nil {
		t.Fatal("CMS accepted unexpected signer")
	}
	v.options.CertificateDER = cert
	if err = v.cms(cms, [][]byte{primary, primary}); err == nil {
		t.Fatal("alternate directory without signed hash agility accepted")
	}
}
