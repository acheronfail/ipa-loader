package apple

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func unavailableResponse() *http.Response {
	response := reply([]byte("private-response-token user@example.invalid"))
	response.StatusCode = http.StatusServiceUnavailable
	response.Header.Set("Location", "https://gsa.apple.com/private-response-token")
	response.Header.Set("X-Apple-Identity-Token", "private-response-token")
	return response
}
func assertUnavailableStage(t *testing.T, err error, stage string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), stage) || !strings.Contains(err.Error(), "Service Unavailable") {
		t.Fatalf("Missing safe protocol-stage failure: %v", err)
	}
	var apple *Error
	if !errors.As(err, &apple) || apple.Code != 503 {
		t.Fatal("HTTP status code was not preserved")
	}
	for _, private := range []string{"private-response-token", "private-request-token", "user@example.invalid", "654321", "gsa.apple.com", "developerservices2.apple.com"} {
		if strings.Contains(err.Error(), private) {
			t.Fatal("Failure exposed private request/response data")
		}
	}
}
func TestTrustedValidation503DoesNotResubmitCode(t *testing.T) {
	c := New(testHeaders)
	calls, challenges := 0, 0
	c.HTTPClient.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		switch calls {
		case 1:
			if r.Method != "GET" || r.URL.Path != "/auth/verify/trusteddevice" {
				t.Fatal("Wrong trusted delivery request")
			}
			return reply(nil), nil
		case 2:
			if r.Method != "GET" || r.URL.Path != "/grandslam/GsService2/validate" || r.Header.Get("security-code") != "654321" || r.Header.Get("X-Apple-Identity-Token") == "" {
				t.Fatal("Wrong trusted validation route or headers")
			}
			return unavailableResponse(), nil
		default:
			t.Fatal("Verification code request retried after HTTP503")
			return nil, nil
		}
	})
	headers, _ := testHeaders(context.Background())
	err := c.twoFactor(context.Background(), map[string]any{"adsid": "private-request-token", "GsIdmsToken": "private-request-token"}, headers, "trusted", func(ch Challenge) (string, error) { challenges++; return "654321", nil }, false)
	assertUnavailableStage(t, err, "trusted-device code validation")
	if calls != 2 || challenges != 1 {
		t.Fatal("Verification retry or prompt count changed")
	}
}
func TestSMSValidation503DoesNotResubmitCode(t *testing.T) {
	c := New(testHeaders)
	calls, challenges := 0, 0
	c.HTTPClient.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		switch calls {
		case 1:
			return reply([]byte(`{"trustedPhoneNumbers":[{"id":7,"number":"***7"}]}`)), nil
		case 2:
			if r.Method != "PUT" || r.URL.Path != "/auth/verify/phone" {
				t.Fatal("Wrong SMS delivery request")
			}
			return reply(nil), nil
		case 3:
			if r.Method != "POST" || r.URL.Path != "/auth/verify/phone/securitycode" {
				t.Fatal("Wrong SMS validation request")
			}
			return unavailableResponse(), nil
		default:
			t.Fatal("SMS code request retried after HTTP503")
			return nil, nil
		}
	})
	headers, _ := testHeaders(context.Background())
	err := c.twoFactor(context.Background(), map[string]any{"adsid": "private-request-token", "GsIdmsToken": "private-request-token"}, headers, "sms", func(ch Challenge) (string, error) { challenges++; return "654321", nil }, false)
	assertUnavailableStage(t, err, "SMS code validation")
	if calls != 3 || challenges != 1 {
		t.Fatal("SMS retry or prompt count changed")
	}
}
func TestGSATransportFailureIdentifiesProtocolStage(t *testing.T) {
	for _, test := range []struct{ operation, stage string }{{"init", "Apple password challenge"}, {"complete", "Apple password proof"}, {"apptokens", "Apple application-token exchange"}} {
		t.Run(test.operation, func(t *testing.T) {
			c := New(testHeaders)
			calls := 0
			c.HTTPClient.Transport = roundTrip(func(r *http.Request) (*http.Response, error) { calls++; return unavailableResponse(), nil })
			headers, _ := testHeaders(context.Background())
			_, err := c.gsa(context.Background(), map[string]any{"o": test.operation, "u": "user@example.invalid", "t": "private-request-token"}, headers)
			assertUnavailableStage(t, err, test.stage)
			if calls != 1 {
				t.Fatal("GSA credential/token request automatically retried")
			}
		})
	}
}
func TestTeamLookupFailureHasSafeStage(t *testing.T) {
	c := New(testHeaders)
	c.HTTPClient.Transport = roundTrip(func(r *http.Request) (*http.Response, error) { return unavailableResponse(), nil })
	_, err := c.Teams(context.Background(), testSession())
	assertUnavailableStage(t, err, "developer-team lookup")
}
func TestRequestFailureDoesNotEchoUnknownURL(t *testing.T) {
	c := New(testHeaders)
	c.HTTPClient.Transport = roundTrip(func(r *http.Request) (*http.Response, error) { return unavailableResponse(), nil })
	_, _, err := c.request(context.Background(), "GET", "https://gsa.apple.com/private-request-token?account=user@example.invalid", map[string]string{"security-code": "654321"}, []byte("private-request-token"))
	assertUnavailableStage(t, err, "Apple authentication")
}
