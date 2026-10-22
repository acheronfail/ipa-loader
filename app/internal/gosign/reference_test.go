package gosign

import (
	"bytes"
	"context"
	"github.com/smallstep/pkcs7"
	"ipa-loader/app/internal/cms"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDeviceValidatedCMSPolicyAndReference(t *testing.T) {
	id := testIdentity(t)
	code := make([]byte, 4096)
	copy(code, []byte("synthetic page"))
	signature, e := signature(code, id, Options{Identifier: "org.example.fixture"}, nil, nil, 4096, 6)
	if e != nil {
		t.Fatal(e)
	}
	var cd, der []byte
	n := int(be.Uint32(signature[8:]))
	for i := 0; i < n; i++ {
		typ, off := be.Uint32(signature[12+8*i:]), int(be.Uint32(signature[16+8*i:]))
		b := signature[off : off+int(be.Uint32(signature[off+4:]))]
		switch typ {
		case 0:
			cd = b
		case 0x1000:
			t.Fatal("SHA1/alternate directory reintroduced; current device policy is SHA256-only")
		case 0x10000:
			der = b[8:]
		}
	}
	if len(cd) < 88 || cd[37] != 2 {
		t.Fatal("missing SHA256 CodeDirectory")
	}
	p, e := pkcs7.Parse(der)
	if e != nil {
		t.Fatal(e)
	}
	if len(p.Signers) != 1 || !p.Signers[0].DigestEncryptionAlgorithm.Algorithm.Equal(pkcs7.OIDEncryptionAlgorithmRSASHA256) {
		t.Fatal("CMS RSA algorithm policy differs from device-validated encoding")
	}
	found1, found2 := false, false
	for _, a := range p.Signers[0].AuthenticatedAttributes {
		switch a.Type.String() {
		case "1.2.840.113635.100.9.1":
			found1 = true
		case "1.2.840.113635.100.9.2":
			found2 = true
		}
	}
	if !found1 || !found2 {
		t.Fatal("Apple signed hash attributes missing")
	}
	if _, _, _, e = cms.Verify(der, cd, id.Certificate.Raw); e != nil {
		t.Fatal(e)
	}
	reference := os.Getenv("IPA_LOADER_TEST_OPENSSL")
	if reference == "" {
		return
	}
	if !filepath.IsAbs(reference) {
		t.Fatal("reference OpenSSL must be explicit and absolute")
	}
	work := t.TempDir()
	sig, content, out := filepath.Join(work, "signature.der"), filepath.Join(work, "directory.bin"), filepath.Join(work, "verified.bin")
	os.WriteFile(sig, der, 0600)
	os.WriteFile(content, cd, 0600)
	run := func() error {
		return exec.CommandContext(context.Background(), reference, "cms", "-verify", "-binary", "-inform", "DER", "-in", sig, "-content", content, "-noverify", "-out", out).Run()
	}
	if e = run(); e != nil {
		t.Fatal("OpenSSL rejected Go-generated signature", e)
	}
	actual, e := os.ReadFile(out)
	if e != nil || !bytes.Equal(actual, cd) {
		t.Fatal("reference returned different content", e)
	}
	cd[len(cd)-1] ^= 1
	os.WriteFile(content, cd, 0600)
	if run() == nil {
		t.Fatal("reference accepted changed CodeDirectory")
	}
}
