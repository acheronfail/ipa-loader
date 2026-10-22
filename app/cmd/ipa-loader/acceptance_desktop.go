//go:build linux || darwin

package main

import (
	"context"
	"flag"
	"fmt"
	"ipa-loader/app/internal/accounts"
	"ipa-loader/app/internal/apple"
	"ipa-loader/app/internal/authclient"
	"ipa-loader/app/internal/ipa"
	"ipa-loader/app/internal/platform"
	"os"
	"path/filepath"
	"time"
)

// Explicit acceptance mode uses the same saved session and production install
// pipeline as the GUI. It is restricted to this project's owned test fixtures.
func fixtureCommand() bool {
	if len(os.Args) < 2 || os.Args[1] != "--test-fixture" {
		return false
	}
	flags := flag.NewFlagSet("fixture acceptance", flag.ContinueOnError)
	input := flags.String("test-fixture", "", "absolute owned fixture IPA")
	name := flags.String("device-name", "", "exact test iPhone name")
	transport := flags.String("transport", "usb", "observed route: usb or wifi")
	if err := flags.Parse(os.Args[1:]); err != nil || flags.NArg() != 0 {
		os.Exit(1)
	}
	if err := installTestFixture(*input, *name, *transport); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return true
}
func installTestFixture(input, name, transport string) error {
	if !filepath.IsAbs(input) || name == "" || transport != "usb" && transport != "wifi" {
		return fmt.Errorf("select an absolute fixture path, exact device name, and usb or wifi transport")
	}
	info, err := ipa.Inspect(input)
	if err != nil {
		return err
	}
	if info.BundleID != "org.ipaloader.frameworktest" && info.BundleID != "org.ipaloader.windowsfixture" {
		return fmt.Errorf("acceptance mode requires an owned framework or sharing fixture")
	}
	state, err := accounts.Native().Load()
	if err != nil {
		return err
	}
	var session *apple.Session
	for _, s := range state.Sessions {
		if accounts.Key(s.Username) == accounts.Key(state.Active) {
			session = s
		}
	}
	if session == nil {
		return fmt.Errorf("sign in using the GUI before running fixture acceptance")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	client := authclient.New()
	teams, err := client.Teams(ctx, session)
	if err != nil {
		return err
	}
	if len(teams) != 1 {
		return fmt.Errorf("acceptance requires one unambiguous team")
	}
	devices, err := platform.Devices(ctx)
	if err != nil {
		return err
	}
	selected, err := selectFixtureDevice(devices, name, transport)
	if err != nil {
		return err
	}
	fmt.Printf("Using observed %s route for fixture acceptance\n", selected.Transport)
	result, err := platform.Sideload(ctx, client, session, teams[0].ID, input, selected, func(p platform.Progress) { fmt.Println(p.Message) })
	if err != nil {
		return err
	}
	if !result.Installed {
		return fmt.Errorf("installation not confirmed")
	}
	fmt.Printf("Fixture installation confirmed: %s, version %s, build %s\n", info.BundleID, result.Version, result.Build)
	return nil
}

// Route selection is exact: a Wi-Fi acceptance run must never fall back to USB.
func selectFixtureDevice(devices []platform.Device, name, transport string) (platform.Device, error) {
	route := map[string]string{"usb": "USB", "wifi": "WiFi"}[transport]
	if name == "" || route == "" {
		return platform.Device{}, fmt.Errorf("select an exact device name and usb or wifi transport")
	}
	var selected *platform.Device
	for i := range devices {
		if devices[i].Name != name || devices[i].Transport != route {
			continue
		}
		if selected != nil {
			return platform.Device{}, fmt.Errorf("ambiguous %s test device", route)
		}
		selected = &devices[i]
	}
	if selected == nil {
		return platform.Device{}, fmt.Errorf("selected %s test device unavailable", route)
	}
	return *selected, nil
}
