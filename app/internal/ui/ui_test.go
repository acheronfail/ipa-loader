package ui

import (
	"context"
	"image/png"
	"os"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
	"ipa-loader/app/internal/accounts"
	"ipa-loader/app/internal/apple"
	"ipa-loader/app/internal/ipa"
	"ipa-loader/app/internal/platform"
)

func TestPickerCancellationPreservesIPAAndPreventsDuplicates(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	done := make(chan func(), 4)
	fyne.SetCurrentApp(&accountTestApp{a, &accountTestDriver{a.Driver(), done}})
	w := a.NewWindow("picker cancellation")
	defer w.Close()
	called, release := make(chan string, 2), make(chan struct{})
	s := New(w, Services{ChooseIPA: func(current string) (string, error) {
		called <- current
		<-release
		return "", nil
	}})
	s.showAccount(&apple.Session{Username: "test@example.invalid"}, []apple.Team{{ID: "TEAM", Name: "Test"}})
	previous := &ipa.Info{Path: "/tmp/previous.ipa", Name: "Previous", BundleID: "org.example.previous", Version: "1.0", Build: "1"}
	s.showIPA(previous)
	s.chooseIPA()
	if current := <-called; current != previous.Path {
		t.Fatal("picker did not start from the previous IPA")
	}
	s.chooseIPA()
	close(release)
	waitAccountUpdate(t, done)
	if s.busy || s.selected != previous || len(called) != 0 {
		t.Fatal("cancellation changed selection, left UI busy or opened another picker")
	}
}

func TestLoginFirstAndAccountNavigation(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	w := a.NewWindow("test")
	defer w.Close()
	deviceCalls := 0
	s := New(w, Services{Devices: func(context.Context) ([]platform.Device, error) { deviceCalls++; return nil, nil }})
	s.Start()
	if !s.loginPage.Visible() || s.installPage.Visible() {
		t.Fatal("installation controls visible before login")
	}
	if deviceCalls != 0 {
		t.Fatal("device discovery ran before login")
	}
	if !s.install.Disabled() {
		t.Fatal("sideload enabled before sign-in")
	}
	s.loadIPA("not-read-before-login.ipa")
	if s.selected != nil {
		t.Fatal("IPA selected while signed out")
	}
	s.showAccount(&apple.Session{Username: "sample@example.invalid"}, []apple.Team{{ID: "TEST", Name: "Development", LimitKnown: true, AppIDsUnlimited: true}})
	if s.loginPage.Visible() || !s.installPage.Visible() {
		t.Fatal("login did not advance to installation")
	}
	if s.team.Visible() {
		t.Fatal("unnecessary single-team chooser visible")
	}
	if s.accountName.Text != "sample@example.invalid" || s.accountQuota.Text != "Unlimited App IDs" {
		t.Fatal(s.accountQuota.Text)
	}
	s.password.OnSubmitted("ignored") // Hidden login fields must not restart login.
	s.password.SetText("synthetic")
	s.returnToLogin()
	if s.session != nil || !s.loginPage.Visible() || s.installPage.Visible() || s.password.Text != "" {
		t.Fatal("account header did not return to a cleared login")
	}
}

func TestReadinessAndAccountQuota(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	window := a.NewWindow("test")
	defer window.Close()
	s := New(window, Services{})
	s.showAccount(&apple.Session{Username: "sample@example.invalid"}, []apple.Team{{ID: "TEST", Name: "Development", LimitKnown: true, AppIDsUnlimited: true}})
	s.selected = &ipa.Info{Path: "synthetic.ipa"}
	s.devices = []platform.Device{{ID: "routing-id", Name: "Test iPhone", UDID: "test-device-id", Transport: "USB", Model: "iPhone 15", OSVersion: "18.7.8"}}
	s.device.Options = []string{s.devices[0].Label()}
	s.device.SetSelectedIndex(0)
	s.readiness()
	if s.install.Disabled() {
		t.Fatal("complete selection disabled")
	}
	if !strings.Contains(s.device.Selected, "@USB · test-device-id") {
		t.Fatal("selector omits hardware identity/transport")
	}
	if s.deviceHint.Text != "iPhone 15 · iOS 18.7.8" {
		t.Fatal(s.deviceHint.Text)
	}
	s.setBusy(true)
	if !s.install.Disabled() || !s.choose.Disabled() || !s.switchAccountButton.Disabled() {
		t.Fatal("inputs can change during an operation")
	}
	s.returnToLogin()
	if s.session == nil {
		t.Fatal("account can change during an operation")
	}
	s.setBusy(false)
	s.teams[0] = apple.Team{LimitKnown: true, AppIDLimit: 10}
	s.updateQuota()
	if !strings.Contains(s.accountQuota.Text, "Up to 10 App IDs every 7 days") {
		t.Fatal(s.accountQuota.Text)
	}
	s.teams[0] = apple.Team{LimitKnown: true, AppIDLimit: 10, AvailabilityKnown: true, AppIDsAvailable: 4}
	s.updateQuota()
	if s.accountQuota.Text != "4 of 10 App IDs available" {
		t.Fatal(s.accountQuota.Text)
	}
	s.teams[0] = apple.Team{}
	s.updateQuota()
	if !strings.Contains(s.accountQuota.Text, "App ID limit not provided by Apple") {
		t.Fatal(s.accountQuota.Text)
	}
}

func TestMultipleTeamsRequireChoice(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	w := a.NewWindow("test")
	defer w.Close()
	s := New(w, Services{})
	s.showAccount(&apple.Session{Username: "sample@example.invalid"}, []apple.Team{{ID: "ONE", Name: "One", LimitKnown: true, AppIDLimit: 10}, {ID: "TWO", Name: "Two", LimitKnown: true, AppIDsUnlimited: true}})
	if !s.team.Visible() || s.team.SelectedIndex() != -1 || !s.install.Disabled() {
		t.Fatal("multiple teams must not be chosen silently")
	}
	s.team.SetSelectedIndex(1)
	if !strings.Contains(s.accountQuota.Text, "Unlimited App IDs") {
		t.Fatal("team change did not update header")
	}
}

func TestInputAndCancellation(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	w := a.NewWindow("test")
	defer w.Close()
	called := false
	s := New(w, Services{Login: func(context.Context, string, string, func(apple.Challenge) (string, error)) (*apple.Session, error) {
		called = true
		return nil, nil
	}})
	s.login()
	if called {
		t.Fatal("empty credentials submitted")
	}
	if !s.accountStatus.Visible() {
		t.Fatal("missing input feedback")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.setBusy(true)
	if !s.loginCancel.Visible() || s.cancelButton.Visible() {
		t.Fatal("login cancellation belongs on the login screen")
	}
	s.loginCancel.OnTapped()
	if ctx.Err() == nil {
		t.Fatal("cancel did not cancel sign-in")
	}
	s.setBusy(false)
	if s.loginCancel.Visible() {
		t.Fatal("cancel remained visible after completion")
	}
}

func TestLayoutSnapshot(t *testing.T) {
	output := os.Getenv("IPA_LOADER_SCREENSHOT")
	if output == "" {
		t.Skip("optional local layout artifact")
	}
	a := test.NewApp()
	defer a.Quit()
	a.Settings().SetTheme(NewTheme())
	w := a.NewWindow("IPA Loader")
	defer w.Close()
	s := New(w, Services{})
	if state := os.Getenv("IPA_LOADER_SCREENSHOT_STATE"); state == "signed-in" || state == "accounts" {
		s.showAccount(&apple.Session{Username: "sample@example.invalid"}, []apple.Team{{ID: "TEST", Name: "Development", LimitKnown: true, AppIDsUnlimited: true}})
		s.devices = []platform.Device{{ID: "routing-test", Name: "Test iPhone", UDID: "00000000-TESTDEVICE0001", Transport: "USB", Model: "iPhone 15", OSVersion: "18.7.8"}}
		s.device.Options = []string{s.devices[0].Label()}
		s.device.SetSelectedIndex(0)
		if state == "accounts" {
			s.applySavedAccounts(accounts.Snapshot{Sessions: []*apple.Session{{Username: "sample@example.invalid"}, {Username: "another@example.invalid"}}})
		}
	}
	w.Show()
	f, err := os.Create(output)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = png.Encode(f, w.Canvas().Capture()); err != nil {
		t.Fatal(err)
	}
}

func TestVerificationCodeKeyboardSubmission(t *testing.T) {
	for _, key := range []fyne.KeyName{fyne.KeyReturn, fyne.KeyEnter} {
		t.Run(string(key), func(t *testing.T) {
			a := test.NewApp()
			defer a.Quit()
			a.Settings().SetTheme(NewTheme())
			updates := make(chan func(), 4)
			fyne.SetCurrentApp(&accountTestApp{a, &accountTestDriver{a.Driver(), updates}})
			w := a.NewWindow("verification")
			defer w.Close()
			s := New(w, Services{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan string, 1)
			go func() {
				value, err := s.challenge(ctx, apple.Challenge{Kind: "code", Message: "Enter your verification code."})
				if err != nil {
					result <- "error: " + err.Error()
					return
				}
				result <- value
			}()
			waitAccountUpdate(t, updates)
			code, ok := w.Canvas().Focused().(*widget.Entry)
			if !ok || code.Password {
				t.Fatal("verification code must be focused and visible")
			}
			for _, invalid := range []string{"", "12345", "1234567", "12345x"} {
				code.SetText(invalid)
				code.TypedKey(&fyne.KeyEvent{Name: key})
				select {
				case <-result:
					t.Fatal("invalid code submitted")
				default:
				}
			}
			code.SetText("012345")
			code.TypedKey(&fyne.KeyEvent{Name: key})
			select {
			case value := <-result:
				if value != "012345" {
					t.Fatal("verification code changed:", value)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Enter did not submit verification")
			}
			if code.Text != "" {
				t.Fatal("verification code was not cleared")
			}
		})
	}
}
