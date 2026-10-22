package apple

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

func syntheticDevelopmentCertificate(t *testing.T, serial int64, team string, names ...string) map[string]any {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	name := "Synthetic Development"
	if len(names) > 0 {
		name = names[0]
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name, OrganizationalUnit: []string{team}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"certContent": der, "machineName": "Synthetic host"}
}

func TestLegacyQuotaUsesSameCSRForOneUnifiedIssuance(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "Synthetic retained request"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))
	template := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "Apple Development: Synthetic", OrganizationalUnit: []string{"TEAM1"}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"success", "wrong-key", "quota", "invalid-entity", "lost-response"} {
		t.Run(mode, func(t *testing.T) {
			client := New(testHeaders)
			legacy, unified := 0, 0
			client.HTTPClient.Transport = roundTrip(func(request *http.Request) (*http.Response, error) {
				if strings.HasSuffix(request.URL.Path, "/submitDevelopmentCSR.action") {
					legacy++
					return reply(encoded(map[string]any{"resultCode": 7460})), nil
				}
				if request.URL.Path != "/services/v1/certificates" || request.Method != "POST" || request.Header.Get("X-HTTP-Method-Override") != "" {
					t.Fatal("unexpected mutation or unified issuance route")
				}
				unified++
				var payload struct {
					Data struct {
						Type       string
						Attributes map[string]string
					}
				}
				if json.NewDecoder(request.Body).Decode(&payload) != nil || payload.Data.Type != "certificates" || payload.Data.Attributes["csrContent"] != csrPEM || payload.Data.Attributes["certificateType"] != "DEVELOPMENT" || payload.Data.Attributes["teamId"] != "TEAM1" || len(payload.Data.Attributes) != 3 {
					t.Fatal("unified issuance changed the CSR or team")
				}
				if mode == "lost-response" {
					return nil, errors.New("synthetic uncertain issuance")
				}
				if mode == "quota" || mode == "invalid-entity" {
					detail := "You already have a current Development certificate or a pending certificate request."
					if mode == "invalid-entity" {
						detail = "Invalid entity private-response-token"
					}
					data, _ := json.Marshal(map[string]any{"errors": []any{map[string]string{"code": "ENTITY_ERROR", "detail": detail}}})
					response := reply(data)
					response.StatusCode = 409
					return response, nil
				}
				certificate := der
				if mode == "wrong-key" {
					certificate = syntheticDevelopmentCertificate(t, 42, "TEAM1")["certContent"].([]byte)
				}
				data, _ := json.Marshal(map[string]any{"data": map[string]any{"type": "certificates", "id": "CREATED-ID", "attributes": map[string]any{"certificateContent": certificate}}})
				response := reply(data)
				response.StatusCode = 201
				return response, nil
			})
			_, err := client.Request(context.Background(), testSession(), "submitDevelopmentCSR", map[string]any{"csrContent": csrPEM, "machineId": "retained-request"}, "TEAM1")
			if mode == "success" && err != nil || mode != "success" && err == nil {
				t.Fatal("wrong issuance outcome", err)
			}
			if mode == "quota" {
				var quota *Error
				if !errors.As(err, &quota) || quota.Code != 7460 {
					t.Fatal("explicit unified quota not recognized", err)
				}
			}
			if mode == "invalid-entity" {
				var quota *Error
				if !errors.As(err, &quota) || quota.Code == 7460 || strings.Contains(err.Error(), "private-response-token") {
					t.Fatal("unrelated 409 treated as quota or leaked response", err)
				}
			}
			if legacy != 1 || unified != 1 {
				t.Fatal("issuance retried or revoked certificates", legacy, unified)
			}
		})
	}
}

func TestUncertainLegacyIssuanceNeverSubmitsUnifiedCSR(t *testing.T) {
	for _, mode := range []string{"lost-response", "service-unavailable", "expired-session"} {
		t.Run(mode, func(t *testing.T) {
			client := New(testHeaders)
			calls := 0
			client.HTTPClient.Transport = roundTrip(func(request *http.Request) (*http.Response, error) {
				calls++
				if !strings.HasSuffix(request.URL.Path, "/submitDevelopmentCSR.action") {
					t.Fatal("uncertain or unrelated failure triggered another issuance")
				}
				switch mode {
				case "lost-response":
					return nil, errors.New("synthetic lost issuance response")
				case "service-unavailable":
					response := reply([]byte("private-response-token"))
					response.StatusCode = 503
					return response, nil
				default:
					return reply(encoded(map[string]any{"resultCode": 1100})), nil
				}
			})
			_, err := client.Request(context.Background(), testSession(), "submitDevelopmentCSR", map[string]any{"csrContent": "synthetic retained CSR"}, "TEAM1")
			if err == nil || calls != 1 || strings.Contains(err.Error(), "private-response-token") {
				t.Fatal("issuance failure retried or exposed private response", err)
			}
		})
	}
}

func TestUnifiedCertificateRevocationUsesFreshPortalIDAndEmpty204(t *testing.T) {
	certificate := syntheticDevelopmentCertificate(t, 42, "TEAM1", "Apple Development: Synthetic")
	certificate["certificateId"] = "CONFIRMED-ID"
	client := New(testHeaders)
	revocations := 0
	client.HTTPClient.Transport = roundTrip(func(request *http.Request) (*http.Response, error) {
		if strings.HasSuffix(request.URL.Path, "/listAllDevelopmentCerts.action") {
			list := []any{certificate}
			if revocations > 0 {
				list = []any{}
			}
			return reply(encoded(map[string]any{"resultCode": 0, "certificates": list})), nil
		}
		revocations++
		if request.Method != "POST" || request.URL.Path != "/services/v1/certificates/CONFIRMED-ID" || request.Header.Get("X-HTTP-Method-Override") != "DELETE" || request.Header.Get("Content-Type") != "application/vnd.api+json" || request.Header.Get("Accept") != "application/vnd.api+json" || request.Header.Get("X-Apple-GS-Token") != "private-token" {
			t.Fatal("incorrect unified certificate route or headers")
		}
		var payload map[string]string
		if json.NewDecoder(request.Body).Decode(&payload) != nil || len(payload) != 1 || payload["urlEncodedQueryParams"] != "teamId=TEAM1" {
			t.Fatal("incorrect unified certificate payload")
		}
		response := reply(nil)
		response.StatusCode = http.StatusNoContent
		return response, nil
	})
	certs, err := client.DevelopmentCertificates(context.Background(), testSession(), "TEAM1")
	if err != nil || len(certs) != 1 || certs[0].Kind != "Apple Development" {
		t.Fatal("unified inventory failed", err)
	}
	selected := certs[0]
	selected.portalID, selected.Kind = "TAMPERED-ID", "iOS Development"
	if err := client.RevokeDevelopmentCertificate(context.Background(), testSession(), "TEAM1", selected); err != nil {
		t.Fatal(err)
	}
	if revocations != 1 {
		t.Fatal("unified certificate revocation retried")
	}
}

func TestUnifiedCertificateInvalidIdentifierAndUncertainResultNeverFallBack(t *testing.T) {
	for _, id := range []string{"", "../outside", "CERTID"} {
		t.Run("identifier-"+id, func(t *testing.T) {
			certificate := syntheticDevelopmentCertificate(t, 42, "TEAM1", "Apple Development: Synthetic")
			certificate["certificateId"] = id
			client := New(testHeaders)
			mutations := 0
			client.HTTPClient.Transport = roundTrip(func(request *http.Request) (*http.Response, error) {
				if strings.HasSuffix(request.URL.Path, "/listAllDevelopmentCerts.action") {
					return reply(encoded(map[string]any{"resultCode": 0, "certificates": []any{certificate}})), nil
				}
				mutations++
				if request.URL.Path != "/services/v1/certificates/CERTID" {
					t.Fatal("invalid path or legacy fallback attempted")
				}
				return nil, errors.New("synthetic lost response")
			})
			certs, err := client.DevelopmentCertificates(context.Background(), testSession(), "TEAM1")
			if err != nil {
				t.Fatal(err)
			}
			if err := client.RevokeDevelopmentCertificate(context.Background(), testSession(), "TEAM1", certs[0]); err == nil {
				t.Fatal("invalid or uncertain revocation reported success")
			}
			want := 0
			if id == "CERTID" {
				want = 1
			}
			if mutations != want {
				t.Fatal("unexpected mutation count", mutations)
			}
		})
	}
}

func TestExplicitCertificateRevocationRevalidatesAndVerifiesOneTarget(t *testing.T) {
	first := syntheticDevelopmentCertificate(t, 10, "TEAM1")
	second := syntheticDevelopmentCertificate(t, 20, "TEAM1")
	client := New(testHeaders)
	revocations, lists := 0, 0
	client.HTTPClient.Transport = roundTrip(func(request *http.Request) (*http.Response, error) {
		if strings.HasSuffix(request.URL.Path, "/listAllDevelopmentCerts.action") {
			lists++
			certs := []any{first, second}
			if revocations == 1 {
				certs = []any{second}
			}
			return reply(encoded(map[string]any{"resultCode": 0, "certificates": certs})), nil
		}
		if !strings.HasSuffix(request.URL.Path, "/revokeDevelopmentCert.action") {
			t.Fatal("unexpected operation")
		}
		revocations++
		data, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		body, err := parsePlist(data)
		if err != nil || body["serialNumber"] != "A" || body["teamId"] != "TEAM1" || len(body) != 6 {
			t.Fatal("revocation did not select exactly the confirmed certificate", err)
		}
		return reply(encoded(map[string]any{"resultCode": 0})), nil
	})
	ctx := context.Background()
	certs, err := client.DevelopmentCertificates(ctx, testSession(), "TEAM1")
	if err != nil || len(certs) != 2 {
		t.Fatal("inventory failed", err)
	}
	var selected DevelopmentCertificate
	for _, cert := range certs {
		if cert.Serial == "A" {
			selected = cert
		}
	}
	if err := client.RevokeDevelopmentCertificate(ctx, testSession(), "TEAM1", selected); err != nil {
		t.Fatal(err)
	}
	if revocations != 1 || lists != 3 {
		t.Fatal("did not refresh before and verify after one revocation")
	}
}

func TestCertificateRevocationRejectsMissingChangedAndForeignSelection(t *testing.T) {
	first := syntheticDevelopmentCertificate(t, 10, "TEAM1")
	replacement := syntheticDevelopmentCertificate(t, 10, "TEAM1")
	for _, mode := range []string{"missing", "changed", "wrong-team", "cancelled", "empty-selection"} {
		t.Run(mode, func(t *testing.T) {
			client := New(testHeaders)
			selectionPhase := true
			client.HTTPClient.Transport = roundTrip(func(request *http.Request) (*http.Response, error) {
				if !strings.HasSuffix(request.URL.Path, "/listAllDevelopmentCerts.action") {
					t.Fatal("unconfirmed revocation submitted")
				}
				certs := []any{first}
				if !selectionPhase {
					switch mode {
					case "missing":
						certs = []any{}
					case "changed":
						certs = []any{replacement}
					case "wrong-team":
						certs = []any{syntheticDevelopmentCertificate(t, 10, "OTHERTEAM")}
					case "cancelled", "empty-selection":
						t.Fatal("invalid/cancelled selection reached network")
					}
				}
				return reply(encoded(map[string]any{"resultCode": 0, "certificates": certs})), nil
			})
			certs, err := client.DevelopmentCertificates(context.Background(), testSession(), "TEAM1")
			if err != nil {
				t.Fatal(err)
			}
			selectionPhase = false
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			selected := certs[0]
			if mode == "cancelled" {
				cancel()
			}
			if mode == "empty-selection" {
				selected = DevelopmentCertificate{}
			}
			if err := client.RevokeDevelopmentCertificate(ctx, testSession(), "TEAM1", selected); err == nil {
				t.Fatal("invalid selection accepted")
			}
		})
	}
}

func TestCertificateRevocationUncertainResponseNeverRetries(t *testing.T) {
	first := syntheticDevelopmentCertificate(t, 10, "TEAM1")
	client := New(testHeaders)
	revocations := 0
	client.HTTPClient.Transport = roundTrip(func(request *http.Request) (*http.Response, error) {
		if strings.HasSuffix(request.URL.Path, "/revokeDevelopmentCert.action") {
			revocations++
			return nil, errors.New("synthetic connection lost after submission")
		}
		return reply(encoded(map[string]any{"resultCode": 0, "certificates": []any{first}})), nil
	})
	certs, err := client.DevelopmentCertificates(context.Background(), testSession(), "TEAM1")
	if err != nil {
		t.Fatal(err)
	}
	err = client.RevokeDevelopmentCertificate(context.Background(), testSession(), "TEAM1", certs[0])
	if err == nil || !strings.Contains(err.Error(), "not confirmed") || revocations != 1 {
		t.Fatal("uncertain revocation was retried or treated as confirmed", err)
	}
}
