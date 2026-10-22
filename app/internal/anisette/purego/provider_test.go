package purego

import (
	"context"
	"encoding/base64"
	"howett.net/plist"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestProvisionRejectsUntrustedLookupDestination(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != lookupURL {
			t.Fatal("untrusted endpoint reached")
		}
		b, e := plist.Marshal(map[string]any{"urls": map[string]any{"midStartProvisioning": "https://example.invalid/start", "midFinishProvisioning": "https://gsa.apple.com/finish"}}, plist.XMLFormat)
		if e != nil {
			t.Fatal(e)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(b))), Header: make(http.Header)}, nil
	})}
	if state, err := Provision(context.Background(), client); err == nil || state != nil || calls != 1 {
		t.Fatal("untrusted lookup destination accepted", err, calls)
	}
}

func TestProvisionEndpointRestrictions(t *testing.T) {
	for _, address := range []string{"http://gsa.apple.com/", "https://apple.com.example.invalid/", "https://gsa.apple.com:444/", "https://secret@gsa.apple.com/", "https://gsa.apple.com/#fragment", "file:///tmp/secret"} {
		if approvedURL(address) {
			t.Errorf("unsafe URL accepted %q", address)
		}
	}
	if !approvedURL(lookupURL) {
		t.Fatal("valid Apple HTTPS URL rejected")
	}
}

func TestProvisionErrorDoesNotExposeRemoteResponse(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader("private response marker")), Header: make(http.Header)}, nil
	})}
	_, err := Provision(context.Background(), client)
	if err == nil || strings.Contains(err.Error(), "private response marker") {
		t.Fatal("remote response leaked", err)
	}
}

func TestHeadersRetainMachineIdentityAndHonorCancellation(t *testing.T) {
	s := &State{Version: 1, DeviceID: "synthetic-device", LocalUser: strings.Repeat("A", 64), Routing: "17106176"}
	s.Machine.Environment = -2
	for i := range s.Machine.MID {
		s.Machine.MID[i] = byte(i)
	}
	h, err := s.Headers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	mid, err := base64.StdEncoding.DecodeString(h["X-Apple-I-MD-M"])
	if err != nil || string(mid) != string(s.Machine.MID[:]) {
		t.Fatal("MID did not survive provider boundary")
	}
	otp, err := base64.StdEncoding.DecodeString(h["X-Apple-I-MD"])
	if err != nil || len(otp) != 28 {
		t.Fatal("invalid OTP encoding")
	}
	if len(h) != 10 || h["X-Mme-Device-Id"] != s.DeviceID || h["X-Apple-I-MD-RINFO"] != s.Routing {
		t.Fatal("metadata inconsistent")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if h, err := s.Headers(ctx); err == nil || h != nil {
		t.Fatal("cancelled provider returned secret headers")
	}
}
