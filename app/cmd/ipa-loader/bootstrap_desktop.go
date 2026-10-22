//go:build darwin || linux || windows

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"ipa-loader/app/internal/accounts"
	"ipa-loader/app/internal/apple"
	"ipa-loader/app/internal/authclient"
	"ipa-loader/app/internal/platform"
	"os"
	"strings"
	"time"
)

func loaderCommand() bool {
	if len(os.Args) < 2 || os.Args[1] != "--install-loader" {
		return false
	}
	flags := flag.NewFlagSet("install loader", flag.ContinueOnError)
	name := flags.String("device-name", "", "exact iPhone name")
	transport := flags.String("transport", "usb", "usb or wifi")
	report := flags.String("report", "", "optional private installation report")
	if err := flags.Parse(os.Args[2:]); err != nil {
		os.Exit(1)
	}
	if err := installLoader(*name, *transport, *report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return true
}
func installLoader(name, transport, report string) error {
	if name == "" || transport != "usb" && transport != "wifi" {
		return fmt.Errorf("select an exact device name and usb or wifi transport")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	devices, err := platform.Devices(ctx)
	if err != nil {
		return err
	}
	var selected *platform.Device
	for _, d := range devices {
		if d.Name == name && strings.EqualFold(d.Transport, transport) {
			if selected != nil {
				return fmt.Errorf("ambiguous device selection")
			}
			copy := d
			selected = &copy
		}
	}
	if selected == nil {
		return fmt.Errorf("selected %s device unavailable", transport)
	}
	saved, err := accounts.Native().Load()
	if err != nil {
		return err
	}
	var session *apple.Session
	for _, s := range saved.Sessions {
		if accounts.Key(s.Username) == accounts.Key(saved.Active) {
			session = s
		}
	}
	if session == nil {
		return fmt.Errorf("sign in through the desktop app first")
	}
	client := authclient.New()
	teams, err := client.Teams(ctx, session)
	if err != nil {
		return err
	}
	if len(teams) != 1 {
		var paid []apple.Team
		for _, team := range teams {
			if team.LimitKnown && team.AppIDsUnlimited {
				paid = append(paid, team)
			}
		}
		if len(paid) != 1 {
			return fmt.Errorf("use the GUI to select a developer team")
		}
		teams = paid
	}
	if teams[0].LimitKnown && teams[0].AppIDsUnlimited {
		fmt.Println("Selected active paid developer team; installing built-in VPN variant")
	}
	var lastMessage string
	var lastUpdate time.Time
	result, err := platform.BootstrapLoader(ctx, client, session, teams[0].ID, *selected, func(p platform.Progress) {
		if p.Message != lastMessage || time.Since(lastUpdate) > time.Second {
			fmt.Println(p.Message)
			lastMessage = p.Message
			lastUpdate = time.Now()
		}
	})
	if report != "" {
		raw, _ := json.MarshalIndent(result, "", "  ")
		if e := os.WriteFile(report, raw, 0600); e != nil {
			return e
		}
	}
	if err != nil {
		return err
	}
	fmt.Println(result.CompletionMessage)
	return nil
}
