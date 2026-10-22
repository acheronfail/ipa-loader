//go:build darwin

// Explicit live acceptance harness for the owned framework or extension fixture. It reads
// only a caller-selected private session and never imports it into the GUI vault.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"ipa-loader/app/internal/apple"
	"ipa-loader/app/internal/authclient"
	"ipa-loader/app/internal/ipa"
	"ipa-loader/app/internal/platform"
)

func run() error {
	input := flag.String("ipa", "", "Owned framework or extension fixture IPA")
	sessionPath := flag.String("session-file", "", "Explicit private lab session file")
	deviceName := flag.String("device-name", "", "Authorized test iPhone name")
	reportPath := flag.String("report", "", "Private result JSON path")
	portalOnly := flag.Bool("portal-only", false, "validate read-only provisioning APIs without an iPhone")
	launchOnly := flag.Bool("launch-only", false, "Resume runtime checks from a successful private install report")
	flag.Parse()
	if !*portalOnly && *deviceName == "" {
		return fmt.Errorf("specify the selected device name")
	}
	if *portalOnly && *launchOnly {
		return fmt.Errorf("portal-only and launch-only cannot be combined")
	}
	if *reportPath == "" {
		return fmt.Errorf("specify a private report path")
	}
	info, err := ipa.Inspect(*input)
	if err != nil || (info.BundleID != "org.ipaloader.frameworktest" && info.BundleID != "org.ipaloader.extensiontest" && info.BundleID != "org.ipaloader.extensiontest.free" && info.BundleID != "org.ipaloader.sharingtest") {
		return fmt.Errorf("expected the owned framework or extension fixture IPA")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	var devices []platform.Device
	if !*portalOnly {
		devices, err = platform.Devices(ctx)
		if err != nil {
			return err
		}
	}
	var selected []platform.Device
	for _, d := range devices {
		if d.Name == *deviceName {
			selected = append(selected, d)
		}
	}
	if !*portalOnly && len(selected) != 1 {
		return fmt.Errorf("test iPhone is unavailable or ambiguous")
	}
	if *launchOnly {
		b, err := os.ReadFile(*reportPath)
		var result platform.Result
		if err != nil || json.Unmarshal(b, &result) != nil || !result.Installed || result.Build != info.Build || result.Version != info.Version || (result.BundleID != info.BundleID && !strings.HasPrefix(result.BundleID, info.BundleID+".")) {
			return fmt.Errorf("report does not identify the installed owned fixture")
		}
		return checkRuntime(ctx, result, selected[0], *reportPath)
	}
	s, err := os.Lstat(*sessionPath)
	if err != nil || !s.Mode().IsRegular() || s.Mode().Perm() != 0600 || s.Size() > 1<<20 {
		return fmt.Errorf("select a private 0600 lab session file")
	}
	b, err := os.ReadFile(*sessionPath)
	if err != nil {
		return fmt.Errorf("could not read lab session")
	}
	var stored struct {
		Format     int    `json:"format"`
		Username   string `json:"username"`
		DSID       string `json:"dsid"`
		Token      string `json:"token"`
		IdentityFP string `json:"identity_fp"`
	}
	defer clear(b)
	if json.Unmarshal(b, &stored) != nil {
		return fmt.Errorf("invalid lab session format")
	}
	var portableSession apple.Session
	if stored.Format == 0 && json.Unmarshal(b, &portableSession) == nil && portableSession.IdentityFP != "" {
		stored.Format = 1
		stored.Username, stored.DSID, stored.Token, stored.IdentityFP = portableSession.Username, portableSession.DSID, portableSession.Token, portableSession.IdentityFP
	}
	if stored.Format != 1 || stored.Token == "" || stored.IdentityFP == "" {
		return fmt.Errorf("invalid lab session format")
	}
	session := &apple.Session{Username: stored.Username, DSID: stored.DSID, Token: stored.Token, IdentityFP: stored.IdentityFP}
	client := authclient.New()
	teams, err := client.Teams(ctx, session)
	if err != nil {
		return err
	}
	if len(teams) != 1 {
		return fmt.Errorf("expected one unambiguous developer team")
	}
	if *portalOnly {
		for _, action := range []string{"listAllDevelopmentCerts", "listDevices", "listAppIds"} {
			if _, err := client.Request(ctx, session, action, nil, teams[0].ID); err != nil {
				return err
			}
			fmt.Println("Read-only developer API succeeded:", action)
		}
		if err := os.MkdirAll(filepath.Dir(*reportPath), 0700); err != nil {
			return fmt.Errorf("could not create private report directory")
		}
		report := []byte(`{"provider":"integrated-pure-go","read_only_portal_checks":["listAllDevelopmentCerts","listDevices","listAppIds"],"succeeded":true}`)
		return os.WriteFile(*reportPath, report, 0600)
	}
	result, installErr := platform.Sideload(ctx, client, session, teams[0].ID, *input, selected[0], func(p platform.Progress) { fmt.Println(p.Message) })
	if err = os.MkdirAll(filepath.Dir(*reportPath), 0700); err != nil {
		return fmt.Errorf("could not create private report directory")
	}
	encoded, _ := json.Marshal(result)
	if err = os.WriteFile(*reportPath, encoded, 0600); err != nil {
		return fmt.Errorf("could not retain private installation result")
	}
	if installErr != nil {
		return installErr
	}
	return checkRuntime(ctx, result, selected[0], *reportPath)
}
func checkRuntime(ctx context.Context, result platform.Result, device platform.Device, reportPath string) error {
	// Retain the complete device console privately; emit only owned fixture text.
	cmd := exec.CommandContext(ctx, "xcrun", "devicectl", "device", "process", "launch", "--device", device.ID, "--terminate-existing", "--console", result.BundleID, "--fixture-check")
	console, launchErr := cmd.CombinedOutput()
	if err := os.WriteFile(filepath.Join(result.WorkDir, "fixture-launch.log"), console, 0600); err != nil {
		return fmt.Errorf("could not retain private launch result")
	}
	marker := "IPA_LOADER_FRAMEWORK build=" + result.Build + " value=42 resource=ok"
	if strings.HasPrefix(result.BundleID, "org.ipaloader.extensiontest") {
		marker = "IPA_LOADER_EXTENSION_HOST build=" + result.Build + " embedded=ok"
	}
	if strings.HasPrefix(result.BundleID, "org.ipaloader.sharingtest") {
		marker = "IPA_LOADER_SHARING_HOST build=" + result.Build + " shared=ok"
	}
	if launchErr != nil || !strings.Contains(string(console), marker) {
		return fmt.Errorf("fixture host runtime check failed; see private launch diagnostics")
	}
	fmt.Println(marker)
	// Leave the fixture's visible result screen open for manual inspection.
	if err := exec.CommandContext(ctx, "xcrun", "devicectl", "device", "process", "launch", "--device", device.ID, result.BundleID).Run(); err != nil {
		return fmt.Errorf("runtime check passed but visible launch failed")
	}
	result.Launched = true
	encoded, _ := json.Marshal(result)
	if err := os.WriteFile(reportPath, encoded, 0600); err != nil {
		return fmt.Errorf("could not retain launch result")
	}
	fmt.Println("Installation and fixture host runtime check passed")
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
