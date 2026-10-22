package apple

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestPortableAuthKitConstructorAndDeveloperIdentity(t *testing.T) {
	const description = "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
	for _, invalid := range []string{"", "<PC> <Windows;6.2>", description + "\r\nInjected: yes", description + "\t", strings.Repeat("x", 4097) + description} {
		if _, err := NewPortableAuthKit(testHeaders, invalid); err == nil {
			t.Fatal("invalid description accepted")
		}
	}
	if _, err := NewPortableAuthKit(nil, description); err == nil {
		t.Fatal("nil provider accepted")
	}
	original, _ := testHeaders(context.Background())
	previous := original["X-MMe-Client-Info"]
	c, err := NewPortableAuthKit(func(context.Context) (map[string]string, error) { return original, nil }, description)
	if err != nil {
		t.Fatal(err)
	}
	headers, err := c.headers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if original["X-MMe-Client-Info"] != previous || headers["X-MMe-Client-Info"] != description || c.HTTPClient.Jar == nil || c.windowsAuthKit {
		t.Fatal("portable constructor changed provider map or native session policy")
	}
	c.HTTPClient.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Hostname() != "developerservices2.apple.com" || r.Header.Get("X-MMe-Client-Info") != description || r.Header.Get("User-Agent") != "Xcode" {
			t.Fatal("developer identity differs from token identity")
		}
		if marked, _ := r.Context().Value(portableSRPContextKey{}).(bool); marked {
			t.Fatal("developer request marked for password transport")
		}
		return reply(encoded(map[string]any{"resultCode": 0, "teams": []any{}})), nil
	})
	_, err = c.Teams(context.Background(), &Session{DSID: "synthetic-dsid", Token: "synthetic-token", IdentityFP: fingerprint(headers)})
	if err != nil {
		t.Fatal(err)
	}
}
