//go:build windows

// Read only an owned fixture's explicit proof file on the named test device.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"ipa-loader/app/internal/mobiledevice"
	"ipa-loader/app/internal/platform"
	"ipa-loader/app/internal/securestore"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func run() error {
	name := flag.String("device-name", "", "exact authorized test iPhone name")
	kind := flag.String("kind", "", "extension, sharing-host, or sharing-extension")
	flag.Parse()
	if *name == "" {
		return errors.New("Select an explicit test device name")
	}
	if *kind != "extension" && *kind != "sharing-host" && *kind != "sharing-extension" {
		return errors.New("Select a supported owned fixture proof")
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return err
	}
	data, err := securestore.Read(filepath.Join(cache, "ipa-loader", "validation", "latest-install.dpapi"), 1<<20)
	if err != nil {
		return err
	}
	defer clear(data)
	var installed platform.Result
	if json.Unmarshal(data, &installed) != nil || !installed.Installed || !(installed.BundleID == "org.ipaloader.windowsfixture" || strings.HasPrefix(installed.BundleID, "org.ipaloader.windowsfixture.")) {
		return errors.New("No confirmed isolated Windows fixture installation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	devices, err := mobiledevice.WindowsDevices(ctx)
	if err != nil {
		return err
	}
	var udid string
	for _, device := range devices {
		if device.Name == *name {
			if udid != "" && udid != device.UDID {
				return errors.New("Ambiguous test device")
			}
			udid = device.UDID
		}
	}
	if udid == "" {
		return errors.New("Selected test device unavailable")
	}
	bundle, document := installed.BundleID, "sharing-proof.json"
	if *kind != "sharing-host" {
		bundle += ".share"
	}
	if *kind == "extension" {
		document = "extension-proof.json"
	}
	proofData, err := mobiledevice.WindowsReadAppDocument(ctx, udid, bundle, document, mobiledevice.DocumentOptions{DeveloperContainer: true})
	if err != nil {
		return err
	}
	defer clear(proofData)
	var proof struct {
		Build     string `json:"build"`
		BundleID  string `json:"bundle_id"`
		Executed  bool   `json:"extension_executed"`
		Extension bool   `json:"extension"`
		AllOK     bool   `json:"all_ok"`
		Counter   int    `json:"counter"`
	}
	if json.Unmarshal(proofData, &proof) != nil || proof.Build != installed.Build {
		return errors.New("Fixture proof build does not match installed build")
	}
	if *kind == "extension" {
		if !proof.Executed || proof.BundleID != bundle {
			return errors.New("Extension execution was not proven")
		}
		fmt.Printf("Extension execution independently confirmed: build=%s.\n", proof.Build)
		return nil
	}
	if !proof.AllOK || proof.Extension != (*kind == "sharing-extension") {
		return errors.New("Sharing proof did not verify all stores and runtime role")
	}
	fmt.Printf("Sharing runtime independently confirmed: role=%s build=%s counter=%d all_ok=true.\n", *kind, proof.Build, proof.Counter)
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
