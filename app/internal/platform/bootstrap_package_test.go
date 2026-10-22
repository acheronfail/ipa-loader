//go:build (darwin && !ios) || linux || windows

package platform

import (
	"context"
	"ipa-loader/app/internal/bootstrap"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuiltIOSLoaderPassesProductionPreflight(t *testing.T) {
	input := os.Getenv("IPA_LOADER_TEST_IOS_IPA")
	if input == "" {
		t.Skip("explicit built iOS payload preflight")
	}
	work, err := privateTempDir("", "ipa-loader-ios-preflight-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(work)
	app, err := extractIPA(context.Background(), input, work)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(input, "-VPN.ipa") {
		if !app.Networking.PacketTunnel || len(app.Embedded) != 1 || !app.Embedded[0].Extension || !app.Embedded[0].Networking.PacketTunnel {
			t.Fatal("VPN package is missing its requested packet tunnel or extension")
		}
	} else if app.Networking.PacketTunnel || len(app.Embedded) != 0 {
		t.Fatal("LocalDevVPN package unexpectedly requires embedded capabilities")
	}
	if app.BundleID != bootstrap.BundleID {
		t.Fatal("wrong loader identity")
	}
	data, err := os.ReadFile(filepath.Join(app.Path, "Info.plist"))
	if err != nil {
		t.Fatal(err)
	}
	meta, err := dictionary(data)
	if err != nil {
		t.Fatal(err)
	}
	if meta["UIFileSharingEnabled"] != true {
		t.Fatal("bootstrap document transfer disabled")
	}
	if _, err = os.Stat(filepath.Join(app.Path, "sharing-ios.zip")); err != nil {
		t.Fatal("missing portable sharing runtime")
	}
	if _, err = os.Stat(filepath.Join(app.Path, "IPALoaderBootstrap.json")); !os.IsNotExist(err) {
		t.Fatal("bootstrap secrets were bundled into a shared release")
	}
}
