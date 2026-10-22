//go:build ios

package iosapp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"ipa-loader/app/internal/accounts"
	"ipa-loader/app/internal/apple"
	"ipa-loader/app/internal/authclient"
	"ipa-loader/app/internal/iosnative"
	"ipa-loader/app/internal/ipa"
	"ipa-loader/app/internal/platform"
)

func Run() {
	os.Setenv("HOME", iosnative.Home())
	setupErr := platform.InitializeIOS()
	client := authclient.New()
	var controller *Controller
	load := func(check bool) any {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		_, connected := iosnative.VPNState()
		if iosnative.HasVPN() && !connected {
			check = false
		}
		apps, err := platform.IOSApps(ctx, check)
		if controller != nil {
			controller.UpdateApps(apps)
		}
		message := ""
		if err != nil {
			message = "Couldn’t check this iPhone. Showing saved dates. Enable Local VPN in Settings and pull down to retry."
		}
		if setupErr != nil {
			message = "Setup needs attention. Connect this iPhone to the desktop app and install IPA Loader again."
		}
		return struct {
			Apps    []platform.IOSApp
			Message string
		}{apps, message}
	}
	services := Services{
		Accounts: accounts.Native(), Login: client.Login, Teams: client.Teams,
		Device: func(ctx context.Context) (platform.Device, error) {
			timeout, cancel := context.WithTimeout(ctx, deviceTimeout)
			defer cancel()
			devices, err := platform.Devices(timeout)
			if err != nil {
				return platform.Device{}, err
			}
			// The on-phone UI only targets the phone configured by desktop setup.
			for _, d := range devices {
				if platform.IsIOSDevice(d) {
					return d, nil
				}
			}
			return platform.Device{}, fmt.Errorf("Couldn’t connect to this iPhone. Check Local VPN in Settings.")
		},
		Refresh: func(ctx context.Context, s *apple.Session, team, id string, d platform.Device, p func(platform.Progress)) (platform.Result, error) {
			return platform.RefreshIOSApp(ctx, client, s, team, id, d, p)
		},
		Install: func(ctx context.Context, s *apple.Session, team, path string, d platform.Device, p func(platform.Progress)) (platform.Result, error) {
			return platform.Sideload(ctx, client, s, team, path, d, p)
		},
		RefreshTeam: platform.IOSRefreshTeam, ChooseIPA: iosnative.ChooseIPA,
		ConfirmIPA: func(info *ipa.Info) (bool, bool, error) { return iosnative.ConfirmImport(info) },
		Ask: func(ch apple.Challenge) (string, error) {
			if ch.Kind == "phone" {
				options := make([]string, len(ch.Phones))
				for i, p := range ch.Phones {
					options[i] = p.Label
				}
				index, err := iosnative.ChooseOption("Send a verification code", options, 0)
				if err != nil || index < 0 {
					return "", context.Canceled
				}
				return strconv.Itoa(ch.Phones[index].ID), nil
			}
			value, err := iosnative.Prompt("Verify your Apple Account", ch.Message, "", false, true, false)
			if err != nil {
				return "", context.Canceled
			}
			return strings.TrimSpace(value), nil
		},
		ConfirmFallback: func(id string) bool {
			_, err := iosnative.Prompt("Original IPA needed", "This app needs full signing. Choose its original IPA to continue. You can optionally keep a copy for future refreshes.", "", false, false, true)
			return err == nil
		},
		Connection: func() error {
			address, save, err := iosnative.ConnectionSettings(iosnative.HasVPN(), platform.IOSDeviceAddress())
			if err == nil && save {
				address = strings.TrimSpace(strings.SplitN(address, "/", 2)[0])
				err = platform.SetIOSDeviceAddress(address)
			}
			return err
		},
		ResetVPN: iosnative.ResetVPN, VPNState: iosnative.VPNState, SetVPN: iosnative.SetVPN,
		Certificates: client.DevelopmentCertificates, Revoke: client.RevokeDevelopmentCertificate,
		Publish: func(state State) {
			iosnative.SetAuthenticated(state.Authenticated)
			iosnative.SetAppsBusy(state.Busy)
			iosnative.UpdateShell(state)
		},
		Reload: func() { iosnative.ReloadApps(true) },
	}
	controller = New(services)
	iosnative.ConfigureApps(load, func(id string) { controller.Handle(Action{Kind: "refresh", Value: id}) })
	iosnative.Run(func() { controller.Handle(Action{Kind: "start"}) }, func(raw []byte) {
		var a Action
		if json.Unmarshal(raw, &a) == nil {
			controller.Handle(a)
		}
	})
}
