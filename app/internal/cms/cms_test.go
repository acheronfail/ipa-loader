package cms

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"github.com/smallstep/pkcs7"
	"math/big"
	"testing"
	"time"
)

func testSigned(t *testing.T, detached, duplicate bool) ([]byte, []byte) {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic CMS test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	cert, e = x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	s, e := pkcs7.NewSignedData([]byte("authenticated content"))
	if e != nil {
		t.Fatal(e)
	}
	s.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	attrs := pkcs7.SignerInfoConfig{}
	if duplicate {
		attrs.ExtraSignedAttributes = []pkcs7.Attribute{{Type: pkcs7.OIDAttributeMessageDigest, Value: []byte("duplicate")}}
	}
	if e = s.AddSigner(cert, key, attrs); e != nil {
		t.Fatal(e)
	}
	if detached {
		s.Detach()
	}
	b, e := s.Finish()
	if e != nil {
		t.Fatal(e)
	}
	return b, der
}
func TestCMSIntegrityBoundaries(t *testing.T) {
	attached, cert := testSigned(t, false, false)
	content, signer, _, e := Verify(attached, nil, cert)
	if e != nil || !bytes.Equal(content, []byte("authenticated content")) || signer == nil {
		t.Fatal(e)
	}
	detached, other := testSigned(t, true, false)
	if _, _, _, e = Verify(detached, content, other); e != nil {
		t.Fatal(e)
	}
	for _, tt := range []struct {
		name              string
		b, data, expected []byte
	}{{"changed content", detached, []byte("changed"), other}, {"unexpected signer", detached, content, cert}, {"attached content not detached", attached, content, cert}, {"trailing data", append(append([]byte{}, attached...), 0), nil, cert}, {"truncated", attached[:len(attached)-1], nil, cert}} {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, _, e := Verify(tt.b, tt.data, tt.expected); e == nil {
				t.Fatal("accepted invalid CMS")
			}
		})
	}
	duplicate, cert := testSigned(t, false, true)
	if _, _, _, e = Verify(duplicate, nil, cert); e == nil {
		t.Fatal("accepted duplicate signed digest attribute")
	}
	// Apple's BER outer sequence is valid; truncation of its EOC is not.
	var outer asn1.RawValue
	if _, e = asn1.Unmarshal(attached, &outer); e != nil {
		t.Fatal(e)
	}
	ber := append(append([]byte{0x30, 0x80}, outer.Bytes...), 0, 0)
	if _, _, _, e = Verify(ber, nil, nil); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = Verify(ber[:len(ber)-1], nil, nil); e == nil {
		t.Fatal("accepted unterminated BER")
	}
}
func FuzzCanonical(f *testing.F) {
	for _, b := range [][]byte{{0x30, 0}, {0x30, 0x80, 0, 0}, {0x24, 0x80, 4, 1, 'x', 0, 0}, {0x30, 0x84, 0xff, 0xff, 0xff, 0xff}} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		d, e := Canonical(b)
		if e == nil {
			again, e := Canonical(d)
			if e != nil || !bytes.Equal(d, again) {
				t.Fatal("canonical output not stable", e)
			}
		}
	})
}
