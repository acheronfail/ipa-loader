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

func TestLoaderIPASelectionByAccount(t *testing.T) {
	root := t.TempDir()
	free := filepath.Join(root, "IPA-Loader-Free-Accounts.ipa")
	paid := filepath.Join(root, "IPA-Loader-Paid-Accounts.ipa")
	for _, path := range []string{free, paid} {
		if err := os.WriteFile(path, []byte("payload"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, account := range []struct {
		name string
		paid bool
		want string
	}{{"free", false, free}, {"paid", true, paid}} {
		t.Run(account.name, func(t *testing.T) {
			got, err := loaderIPAForAccount(free, account.paid)
			if err != nil || got != account.want {
				t.Fatalf("selected %q, %v; want %q", got, err, account.want)
			}
		})
	}
	if err := os.Remove(paid); err != nil {
		t.Fatal(err)
	}
	if _, err := loaderIPAForAccount(free, true); err == nil || !strings.Contains(err.Error(), "IPA-Loader-Paid-Accounts.ipa") {
		t.Fatalf("missing paid package must report its filename, got %v", err)
	}
	if got, err := loaderIPAForAccount(free, false); err != nil || got != free {
		t.Fatalf("free accounts should not require the paid package: %q, %v", got, err)
	}
}

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
	if strings.HasSuffix(input, "-Paid-Accounts.ipa") {
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
