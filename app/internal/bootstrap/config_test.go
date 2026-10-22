package bootstrap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestBootstrapRejectsMismatchedSigningIdentityAndDestination(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{OrganizationalUnit: []string{"ABCDE12345"}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	valid := Config{Version: 1, UDID: "owned-device", Team: "ABCDE12345", InstalledBundleID: BundleID + ".ABCDE12345", Address: DefaultAddress, IPASHA256: strings.Repeat("ab", 32), PairRecord: []byte("opaque pairing"), PrivateKey: x509.MarshalPKCS1PrivateKey(key), Certificate: der}
	raw, _ := json.Marshal(valid)
	if _, err = Decode(raw); err != nil {
		t.Fatal(err)
	}
	valid.Account = "owner@example.invalid"
	raw, _ = json.Marshal(valid)
	if decoded, decodeErr := Decode(raw); decodeErr != nil || decoded.Account != valid.Account {
		t.Fatal("the installing account did not survive setup transfer")
	}
	for _, kind := range []string{"team", "destination", "address", "hash", "private key", "certificate", "version", "pairing size", "account size"} {
		t.Run(kind, func(t *testing.T) {
			c := valid
			switch kind {
			case "team":
				c.Team = "OTHER12345"
			case "destination":
				c.InstalledBundleID = "org.example.other"
			case "address":
				c.Address = "8.8.8.8"
			case "hash":
				c.IPASHA256 = "abcd"
			case "private key":
				c.PrivateKey = []byte("bad")
			case "certificate":
				c.Certificate = []byte("bad")
			case "version":
				c.Version = 2
			case "account size":
				c.Account = strings.Repeat("x", 321)
			case "pairing size":
				c.PairRecord = make([]byte, (1<<20)+1)
			}
			raw, _ := json.Marshal(c)
			if _, err := Decode(raw); err == nil {
				t.Fatal("accepted invalid envelope")
			}
		})
	}
	if strings.Contains(fmt.Sprintf("%+v", valid), "opaque pairing") {
		t.Fatal("bootstrap secrets exposed by formatting")
	}
}

func TestLoaderBundleIDsUseConfiguredNamespace(t *testing.T) {
	for _, id := range []string{BundleID, BundleID + ".ABCDE12345"} {
		if !IsLoaderBundleID(id) {
			t.Fatalf("rejected loader %s", id)
		}
	}
	for _, id := range []string{"org.example.ipaloader.ios", BundleID + ".tunnel", BundleID + ".ABCDE12345.extra", "orgXipaloaderXios"} {
		if IsLoaderBundleID(id) {
			t.Fatalf("accepted unrelated app %s", id)
		}
	}
}
