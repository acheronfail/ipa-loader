//go:build windows

package platform

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"ipa-loader/app/internal/apple"
	"ipa-loader/app/internal/signing"
	"math/big"
	"path/filepath"
	"testing"
	"time"
)

func TestWindowsIdentityIssuanceAndRetainedRequest(t *testing.T) {
	const team = "ABCDE12345"
	for _, retained := range []bool{false, true} {
		t.Run(map[bool]string{false: "new", true: "retained"}[retained], func(t *testing.T) {
			h := &windowsHost{team: team, vault: signing.IdentityVault{Dir: filepath.Join(t.TempDir(), "vault")}}
			e := newControllerTestEngine(context.Background(), t.TempDir())
			e.host = h
			if retained {
				pending, err := h.vault.Prepare(team)
				if err != nil {
					t.Fatal(err)
				}
				if err = h.vault.MarkSubmitted(team, pending.RequestID); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			var der []byte
			portal := portalFunc(func(_ context.Context, _ *apple.Session, action string, p map[string]any, _ string) (map[string]any, error) {
				calls++
				if action == "submitDevelopmentCSR" {
					block, _ := pem.Decode([]byte(p["csrContent"].(string)))
					csr, err := x509.ParseCertificateRequest(block.Bytes)
					if err != nil {
						t.Fatal(err)
					}
					issuer, err := rsa.GenerateKey(rand.Reader, 2048)
					if err != nil {
						t.Fatal(err)
					}
					cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic Development", OrganizationalUnit: []string{team}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(72 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
					der, err = x509.CreateCertificate(rand.Reader, cert, cert, csr.PublicKey, issuer)
					if err != nil {
						t.Fatal(err)
					}
					return map[string]any{}, nil
				}
				if action == "listAllDevelopmentCerts" {
					return map[string]any{"certificates": []any{map[string]any{"certContent": der}}}, nil
				}
				t.Fatal("unexpected portal action")
				return nil, nil
			})
			id, err := e.createOrRecoverIdentity(portal, &apple.Session{}, team, nil)
			if retained {
				if err == nil || id != "" || calls != 0 {
					t.Fatal("retained key caused another CSR")
				}
				return
			}
			if err != nil || id == "" || calls != 2 {
				t.Fatal("new signing identity did not activate")
			}
			identities, err := e.identities()
			if err != nil || !identities[id] {
				t.Fatal("activated identity unavailable")
			}
			calls = 0
			recovered, err := e.createOrRecoverIdentity(portal, &apple.Session{}, team, []map[string]any{{"certContent": der}})
			if err != nil || recovered != id || calls != 0 {
				t.Fatal("existing key/certificate was not reused")
			}
		})
	}
}

func TestWindowsMissingRuntimeStopsBeforeProvisioning(t *testing.T) {
	h := &windowsHost{runtimeErr: errors.New("missing embedded runtime")}
	e := newControllerTestEngine(context.Background(), t.TempDir())
	e.host = h
	if e.checkDeveloperTools() == nil {
		t.Fatal("missing runtime accepted")
	}
}
