//go:build windows

// Windows live harness uses the GUI's saved session and production controller.
// Only isolated, owned Windows fixture identifiers are accepted.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"ipa-loader/app/internal/accounts"
	"ipa-loader/app/internal/apple"
	"ipa-loader/app/internal/authclient"
	"ipa-loader/app/internal/ipa"
	"ipa-loader/app/internal/mobiledevice"
	"ipa-loader/app/internal/platform"
	"ipa-loader/app/internal/securestore"
)

func run() error {
	input := flag.String("ipa", "", "explicit isolated Windows fixture IPA")
	deviceName := flag.String("device-name", "", "exact authorized test iPhone name")
	flag.Parse()
	if *deviceName == "" {
		return errors.New("Select an explicit test device name")
	}
	info, err := ipa.Inspect(*input)
	if err != nil || info.BundleID != "org.ipaloader.windowsfixture" {
		return errors.New("Select an isolated owned Windows fixture IPA")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	devices, err := platform.Devices(ctx)
	if err != nil {
		return err
	}
	var selected []platform.Device
	for _, d := range devices {
		if d.Name == *deviceName {
			selected = append(selected, d)
		}
	}
	if len(selected) != 1 {
		return errors.New("Test iPhone is unavailable or ambiguous")
	}
	locked, err := mobiledevice.WindowsLocked(ctx, selected[0].UDID)
	if err != nil {
		return err
	}
	if locked {
		return errors.New("Unlock the selected test iPhone before installation")
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
		return errors.New("Sign in before running the Windows fixture check")
	}
	client := authclient.New()
	teams, err := client.Teams(ctx, session)
	if err != nil {
		return err
	}
	if len(teams) != 1 {
		return errors.New("Expected one unambiguous developer team")
	}
	fmt.Printf("Selected isolated Windows fixture build %s on %s transport.\n", info.Build, selected[0].Transport)
	result, installErr := platform.Sideload(ctx, client, session, teams[0].ID, *input, selected[0], func(p platform.Progress) { fmt.Println(p.Message) })
	data, err := json.Marshal(result)
	if err != nil {
		return errors.New("Could not encode private fixture result")
	}
	defer clear(data)
	cache, err := os.UserCacheDir()
	if err != nil {
		return errors.New("Could not locate private fixture storage")
	}
	if err = securestore.Write(filepath.Join(cache, "ipa-loader", "validation", "latest-install.dpapi"), data); err != nil {
		return errors.New("Could not retain private fixture result")
	}
	if installErr != nil {
		return installErr
	}
	if !result.Installed {
		return errors.New("Installation was not independently confirmed")
	}
	fmt.Printf("Installation independently confirmed: build=%s submitted=%t.\n", result.Build, result.InstallSubmitted)
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
