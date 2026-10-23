package iosupdate

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"howett.net/plist"
)

type transport func(*http.Request) (*http.Response, error)

func (t transport) RoundTrip(r *http.Request) (*http.Response, error) { return t(r) }
func mockClient(status int, body []byte) *Client {
	return &Client{HTTP: &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "" {
			panic("updater sent credentials")
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
	})}}
}
func packageBytes(t *testing.T, version string, builtin bool) []byte {
	t.Helper()
	var body bytes.Buffer
	z := zip.NewWriter(&body)
	meta, _ := plist.Marshal(map[string]any{"CFBundleIdentifier": "org.ipaloader.ios", "CFBundleShortVersionString": version, "CFBundleVersion": "42"}, plist.XMLFormat)
	f, err := z.Create("Payload/IPA Loader.app/Info.plist")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(meta); err != nil {
		t.Fatal(err)
	}
	if builtin {
		f, err = z.Create("Payload/IPA Loader.app/PlugIns/IPALoaderTunnel.appex/Info.plist")
		if err != nil {
			t.Fatal(err)
		}
		f.Write(meta)
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	return body.Bytes()
}
func releaseFor(body []byte, builtin bool) Release {
	sum := sha256.Sum256(body)
	return Release{Version: "1.2.0", URL: "https://github.com/acheronfail/ipa-loader/releases/download/v1.2.0/" + assetName(builtin), Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:]), BuiltinVPN: builtin}
}
func releaseJSON(r Release, draft, pre bool) []byte {
	raw, _ := json.Marshal(map[string]any{"tag_name": "v" + r.Version, "draft": draft, "prerelease": pre, "assets": []any{map[string]any{"name": assetName(r.BuiltinVPN), "browser_download_url": r.URL, "digest": "sha256:" + r.SHA256, "size": r.Size}}})
	return raw
}
func TestVersionComparison(t *testing.T) {
	for _, tt := range []struct {
		a, b           string
		newer, invalid bool
	}{
		{"1.10.0", "1.9.9", true, false}, {"2.0.0", "1.99.99", true, false}, {"1.0.0", "1.0.0", false, false}, {"0.9.0", "1.0.0", false, false},
		{"1.0.0-beta", "1.0.0", false, true}, {"01.0.0", "1.0.0", false, true}, {"1.0.0", "", false, true},
	} {
		got, err := Newer(tt.a, tt.b)
		if got != tt.newer || (err != nil) != tt.invalid {
			t.Fatalf("%+v: %v %v", tt, got, err)
		}
	}
}
func TestPublishedReleaseSelection(t *testing.T) {
	for _, builtin := range []bool{false, true} {
		r := releaseFor(packageBytes(t, "1.2.0", builtin), builtin)
		for _, tt := range []struct {
			name, current          string
			draft, pre, want, fail bool
			mutate                 func(*Release)
		}{
			{name: "new", current: "1.1.0", want: true},
			{name: "same", current: "1.2.0"}, {name: "older", current: "2.0.0"},
			{name: "draft", current: "1.0.0", draft: true}, {name: "prerelease", current: "1.0.0", pre: true},
			{name: "missing digest", current: "1.0.0", fail: true, mutate: func(r *Release) { r.SHA256 = "" }},
			{name: "wrong host", current: "1.0.0", fail: true, mutate: func(r *Release) { r.URL = "https://example.com/update.ipa" }},
			{name: "wrong variant", current: "1.0.0", fail: true, mutate: func(r *Release) { r.BuiltinVPN = !r.BuiltinVPN }},
		} {
			t.Run(tt.name+assetName(builtin), func(t *testing.T) {
				candidate := r
				if tt.mutate != nil {
					tt.mutate(&candidate)
				}
				got, err := mockClient(200, releaseJSON(candidate, tt.draft, tt.pre)).Check(context.Background(), tt.current, builtin)
				if (got != nil) != tt.want || (err != nil) != tt.fail {
					t.Fatalf("got %+v, %v", got, err)
				}
			})
		}
	}
	for _, code := range []int{404, 403, 429, 500} {
		got, err := mockClient(code, nil).Check(context.Background(), "1.0.0", false)
		if got != nil || (err != nil) != (code != 404) {
			t.Fatal(code, got, err)
		}
	}
}
func TestVerifiedDownloadAndCache(t *testing.T) {
	for _, builtin := range []bool{false, true} {
		body := packageBytes(t, "1.2.0", builtin)
		r := releaseFor(body, builtin)
		path, err := mockClient(200, body).Download(context.Background(), r, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(filepath.Dir(path))
		root := t.TempDir()
		cached, err := SavePackage(context.Background(), root, path)
		if err != nil {
			t.Fatal(err)
		}
		got, err := SavedPackage(root, "1.2.0", "42")
		if err != nil || got != cached {
			t.Fatal(got, err)
		}
		if _, err = SavedPackage(root, "1.1.0", "42"); !os.IsNotExist(err) {
			t.Fatal("old version must not use new IPA", err)
		}
		if err = os.WriteFile(cached, []byte("tampered"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = SavedPackage(root, "1.2.0", "42"); err == nil {
			t.Fatal("tampered fallback accepted")
		}
	}
}
func TestDownloadRejectsInvalidPackages(t *testing.T) {
	good := packageBytes(t, "1.2.0", false)
	for _, name := range []string{"digest", "truncated", "oversized", "version", "variant", "not ipa", "http error"} {
		t.Run(name, func(t *testing.T) {
			body := good
			r := releaseFor(body, false)
			status := 200
			switch name {
			case "digest":
				r.SHA256 = strings.Repeat("0", 64)
			case "truncated":
				body = body[:len(body)-1]
			case "oversized":
				body = append(append([]byte{}, body...), 0)
			case "version":
				body = packageBytes(t, "9.0.0", false)
				r = releaseFor(body, false)
			case "variant":
				body = packageBytes(t, "1.2.0", true)
				r = releaseFor(body, false)
			case "not ipa":
				body = []byte("bad")
				r = releaseFor(body, false)
			case "http error":
				status = 503
			}
			if path, err := mockClient(status, body).Download(context.Background(), r, nil); err == nil || path != "" {
				t.Fatal("invalid update accepted", path, err)
			}
		})
	}
}
func TestCancelledPackageDoesNotReplaceFallback(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(t.TempDir(), "update.ipa")
	os.WriteFile(path, packageBytes(t, "1.2.0", false), 0600)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := SavePackage(ctx, root, path); err != context.Canceled {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 0 {
		t.Fatal("cancelled save retained files", entries)
	}
}

func TestSelfRefreshTracksInstalledVersionAcrossInterruptedUpdate(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(t.TempDir(), "original.ipa")
	candidate := filepath.Join(t.TempDir(), "update.ipa")
	if err := os.WriteFile(original, packageBytes(t, "1.0.0", false), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(candidate, packageBytes(t, "1.2.0", false), 0600); err != nil {
		t.Fatal(err)
	}
	saved, err := SavePackage(context.Background(), root, candidate)
	if err != nil {
		t.Fatal(err)
	}
	// Installation failed or was cancelled: old app must keep its old fallback.
	got, err := RefreshPackage(root, original, "1.0.0", "42")
	if err != nil || got != original {
		t.Fatal("failed update replaced old fallback", got, err)
	}
	// Installation killed the old process: a fresh launch selects the staged IPA.
	got, err = RefreshPackage(root, original, "1.2.0", "42")
	if err != nil || got != saved {
		t.Fatal("new app lost its self-refresh package", got, err)
	}
	if _, err = RefreshPackage(root, original, "1.3.0", "42"); err == nil {
		t.Fatal("would downgrade unknown installed version")
	}
	if _, err = RefreshPackage(root, original, "1.2.0", "43"); err == nil {
		t.Fatal("accepted wrong build")
	}
}
func TestDownloadPreservesCancellation(t *testing.T) {
	c := &Client{HTTP: &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		return nil, context.Canceled
	})}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Download(ctx, releaseFor(packageBytes(t, "1.2.0", false), false), nil); err != context.Canceled {
		t.Fatal(err)
	}
}
