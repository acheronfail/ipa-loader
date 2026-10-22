//go:build !ios

package ui

import (
	"context"
	"errors"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"
	"ipa-loader/app/internal/accounts"
	"ipa-loader/app/internal/apple"
	"ipa-loader/app/internal/ipa"
	"ipa-loader/app/internal/platform"
)

// NewPreview renders the real screen with synthetic data and no account store,
// Apple networking, or device operations. Only cmd/ui-preview and visual tests
// use it; the production executable always constructs NativeServices instead.
func NewPreview(window fyne.Window, state string) *Screen {
	s := New(window, Services{
		Bootstrap: func(context.Context, *apple.Session, string, platform.Device, func(platform.Progress)) (platform.Result, error) {
			return platform.Result{}, errors.New("UI preview does not install IPA Loader")
		},
		DevelopmentCertificates: func(context.Context, *apple.Session, string) ([]apple.DevelopmentCertificate, error) {
			return nil, errors.New("UI preview does not access Apple certificates")
		},
		RevokeDevelopmentCertificate: func(context.Context, *apple.Session, string, apple.DevelopmentCertificate) error {
			return errors.New("UI preview does not revoke certificates")
		},
		Login: func(context.Context, string, string, func(apple.Challenge) (string, error)) (*apple.Session, error) {
			return nil, errors.New("UI preview does not sign in to Apple")
		},
		Teams: func(context.Context, *apple.Session) ([]apple.Team, error) {
			return nil, errors.New("UI preview does not access Apple accounts")
		},
		Sideload: func(context.Context, *apple.Session, string, string, platform.Device, func(platform.Progress)) (platform.Result, error) {
			return platform.Result{}, errors.New("UI preview does not install apps")
		},
	})
	s.accountsLoaded = true
	if state == "login" || state == "" {
		return s
	}
	if state == "login-error" {
		s.accountStatus.SetText("Couldn’t sign in. Check your email and password, then try again.")
		s.accountStatus.Show()
		s.root.Refresh()
		return s
	}
	session := &apple.Session{Username: "alex@example.invalid"}
	if state == "saved-login" {
		s.username.SetText(session.Username)
		s.applySavedAccounts(accounts.Snapshot{Sessions: []*apple.Session{session, {Username: "another@example.invalid"}}})
		s.Window.Resize(fyne.NewSize(460, 560))
		return s
	}
	s.showAccount(session, []apple.Team{{ID: "TEST", Name: "Personal Team"}})
	s.devices = []platform.Device{{ID: "preview-device", Name: "Test iPhone", UDID: "00000000-TESTDEVICE0001", Transport: "USB", Model: "iPhone 15", OSVersion: "18.0"}}
	s.device.Options = []string{desktopDeviceLabel(s.devices[0])}
	s.device.SetSelectedIndex(0)
	if state == "accounts" || state == "account-settings" || state == "account-menu" || state == "manage-accounts" {
		s.teams[0].LimitKnown = true
		s.teams[0].AppIDsUnlimited = true
		s.applySavedAccounts(accounts.Snapshot{Sessions: []*apple.Session{session, {Username: "another@example.invalid"}}})
	}
	if state != "empty" && state != "signed-in" {
		s.showIPA(&ipa.Info{Path: "preview.ipa", Name: "IPA Loader Install Test", Version: "1.0", Build: "1", BundleID: "org.ipaloader.installtest"})
	}
	if state == "long" {
		s.showIPA(&ipa.Info{Path: "preview.ipa", Name: strings.Repeat("A long app name ", 8), Version: "2026.10.21", Build: "123456789", BundleID: "org.example." + strings.Repeat("a-long-identifier.", 6) + "app"})
	}
	if state == "no-device" {
		s.devices = nil
		s.device.Options = nil
		s.device.ClearSelected()
		s.deviceHint.SetText("Connect your iPhone by USB, unlock it, and tap Trust if asked.")
		s.readiness()
	}
	if state == "progress" || state == "details" {
		_, cancel := context.WithCancel(context.Background())
		s.cancel = func() {
			cancel()
			s.cancel = nil
			s.setBusy(false)
			s.installAction.Show()
			s.setStatus("Installation cancelled.")
			s.finishOperation(context.Canceled)
			s.root.Refresh()
		}
		s.installing = true
		s.setBusy(true)
		s.installAction.Show()
		s.status.Importance = widget.MediumImportance
		s.setStatus("Signing and verifying your app…")
		s.progress.SetValue(.6)
		s.progress.Show()
		s.showActivity.Show()
		for _, message := range []string{"Checking IPA compatibility", "Connecting to iPhone", "Reusing signing certificate", "Preparing app identifier", "Downloading provisioning profile", "Signing and verifying app"} {
			s.log(message)
		}
		if state == "details" {
			s.toggleActivity()
		}
	}
	if state == "error" {
		s.status.Importance = widget.MediumImportance
		s.setStatus("Your Apple Account session has expired. Sign in again to continue.")
		s.showActivity.Show()
		s.details.Show()
		s.log("Preparing account signing material")
		s.log("Apple session expired (code 1100)")
	}
	if state == "success" {
		s.status.Importance = widget.MediumImportance
		s.setStatus("Installed on Test iPhone.")
		s.progress.SetValue(1)
		s.progress.Show()
		s.showActivity.Show()
		s.log("Installation confirmed: version 1.0, build 1.")
	}
	if state == "setup" {
		s.taskTabs.Select(s.setupTask)
	}
	if state == "progress" || state == "details" || state == "error" || state == "success" {
		s.showOperation("Installing App…")
		if !s.busy {
			var err error
			if state == "error" {
				err = &apple.Error{Code: 1100, Message: "Session expired"}
			}
			s.finishOperation(err)
		}
	}
	if state == "account-settings" || state == "account-menu" {
		s.showAccountDialog()
	}
	if state == "account-menu" {
		s.showAccountMenu()
	}
	if state == "manage-accounts" {
		s.showSavedAccounts()
	}
	s.root.Refresh()
	return s
}
