package gosign

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"howett.net/plist"
	"io"
	"ipa-loader/app/internal/codesignverify"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func testIdentity(t *testing.T) Identity {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	c := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Pure Go synthetic signer", OrganizationalUnit: []string{"ABCDEFGHIJ"}}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	return Identity{Key: key, Certificate: cert}
}
func TestExistingFixtureSignatures(t *testing.T) {
	id := testIdentity(t)
	for _, name := range []string{"ipa-loader-fixture-v1-unsigned.ipa", "ipa-loader-fixture-v2-unsigned.ipa", "ipa-loader-framework-v1-unsigned.ipa", "ipa-loader-framework-v3-universal.ipa", "ipa-loader-extension-v1-unsigned.ipa", "ipa-loader-extension-v1-free-unsigned.ipa", "ipa-loader-sharing-v12-adhoc.ipa"} {
		t.Run(name, func(t *testing.T) {
			work := t.TempDir()
			z, e := zip.OpenReader(filepath.Join("../../../fixtures/ipas", name))
			if e != nil {
				t.Fatal(e)
			}
			defer z.Close()
			var app string
			for _, f := range z.File {
				p := filepath.Join(work, filepath.FromSlash(f.Name))
				if f.FileInfo().IsDir() {
					if e = os.MkdirAll(p, 0700); e != nil {
						t.Fatal(e)
					}
					continue
				}
				if e = os.MkdirAll(filepath.Dir(p), 0700); e != nil {
					t.Fatal(e)
				}
				r, e := f.Open()
				if e != nil {
					t.Fatal(e)
				}
				b, e := io.ReadAll(r)
				r.Close()
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(p, b, 0700); e != nil {
					t.Fatal(e)
				}
			}
			entries, e := os.ReadDir(filepath.Join(work, "Payload"))
			if e != nil || len(entries) != 1 {
				t.Fatal("fixture payload", e)
			}
			app = filepath.Join(work, "Payload", entries[0].Name())
			var objects []string
			e = filepath.WalkDir(app, func(p string, d os.DirEntry, e error) error {
				if e != nil {
					return e
				}
				if d.IsDir() && (strings.HasSuffix(p, ".app") || strings.HasSuffix(p, ".appex") || strings.HasSuffix(p, ".framework")) || !d.IsDir() && strings.HasSuffix(p, ".dylib") {
					objects = append(objects, p)
				}
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
			sort.Slice(objects, func(i, j int) bool { return len(objects[i]) > len(objects[j]) })
			for _, p := range objects {
				opt := Options{Identifier: filepath.Base(p)}
				s, e := os.Stat(p)
				if e != nil {
					t.Fatal(e)
				}
				if s.IsDir() {
					b, e := os.ReadFile(filepath.Join(p, "Info.plist"))
					if e != nil {
						t.Fatal(e)
					}
					var m map[string]any
					if _, e = plist.Unmarshal(b, &m); e != nil {
						t.Fatal(e)
					}
					opt.Identifier = m["CFBundleIdentifier"].(string)
					if strings.HasSuffix(p, ".app") || strings.HasSuffix(p, ".appex") {
						opt.Entitlements, _ = plist.Marshal(map[string]any{"application-identifier": "ABCDEFGHIJ." + opt.Identifier, "com.apple.developer.team-identifier": "ABCDEFGHIJ", "get-task-allow": true, "keychain-access-groups": []any{"ABCDEFGHIJ." + opt.Identifier}}, plist.XMLFormat)
					}
				}
				if e = Sign(context.Background(), p, id, opt); e != nil {
					t.Fatalf("sign %s: %v", p, e)
				}
				v := codesignverify.Options{CertificateDER: id.Certificate.Raw, Identifier: opt.Identifier, Entitlements: opt.Entitlements, RequireNoEntitlements: len(opt.Entitlements) == 0}
				if s.IsDir() {
					_, e = codesignverify.VerifyBundle(context.Background(), p, v)
				} else {
					_, e = codesignverify.VerifyBinary(context.Background(), p, v)
				}
				if e != nil {
					t.Fatalf("verify %s: %v", p, e)
				}
			}
			// Apple's verifier independently checks the Go-generated signature on
			// macOS, including every universal slice and embedded object.
			if runtime.GOOS == "darwin" {
				if out, err := exec.Command("/usr/bin/codesign", "--verify", "--all-architectures", "--deep", "--strict", app).CombinedOutput(); err != nil {
					t.Fatalf("Apple codesign rejected Go signature: %v\n%s", err, out)
				}
			}
			// Corruption must fail independent verification, including nested sealed data.
			p := filepath.Join(app, "Info.plist")
			b, e := os.ReadFile(p)
			if e != nil {
				t.Fatal(e)
			}
			b = bytes.Replace(b, []byte("<dict>"), []byte("<dict>\n"), 1)
			os.WriteFile(p, b, 0600)
			if _, e = codesignverify.VerifyBundle(context.Background(), app, codesignverify.Options{CertificateDER: id.Certificate.Raw}); e == nil {
				t.Fatal("accepted changed metadata")
			}
		})
	}
}

func TestUniversal64BitDescriptorsAndPaddedSignatures(t *testing.T) {
	id := testIdentity(t)
	z, err := zip.OpenReader("../../../fixtures/ipas/ipa-loader-framework-v1-unsigned.ipa")
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	var input []byte
	for _, f := range z.File {
		if strings.HasSuffix(f.Name, "/libFixtureMath.dylib") {
			r, e := f.Open()
			if e != nil {
				t.Fatal(e)
			}
			input, e = io.ReadAll(r)
			r.Close()
			if e != nil {
				t.Fatal(e)
			}
		}
	}
	if len(input) == 0 {
		t.Fatal("fixture library missing")
	}
	signed, err := thin(input, id, Options{Identifier: "test.library"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	signed = append(signed, make([]byte, 4096)...)
	if _, err = thin(signed, id, Options{Identifier: "test.library"}, nil, nil); err != nil {
		t.Fatal("valid zero allocation padding rejected", err)
	}
	for _, order := range []binary.ByteOrder{be, le} {
		header := make([]byte, 4096)
		order.PutUint32(header, 0xcafebabf)
		order.PutUint32(header[4:], 1)
		copy(header[8:16], input[4:12])
		if order == be {
			be.PutUint32(header[8:], le.Uint32(input[4:]))
			be.PutUint32(header[12:], le.Uint32(input[8:]))
		}
		order.PutUint64(header[16:], 4096)
		order.PutUint64(header[24:], uint64(len(input)))
		order.PutUint32(header[32:], 12)
		out, err := binaryImage(append(header, input...), id, Options{Identifier: "test.library"}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "library")
		os.WriteFile(p, out, 0700)
		if _, err = codesignverify.VerifyBinary(context.Background(), p, codesignverify.Options{CertificateDER: id.Certificate.Raw, Identifier: "test.library", RequireNoEntitlements: true}); err != nil {
			t.Fatal(err)
		}
	}
}
