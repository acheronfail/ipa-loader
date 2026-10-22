package ui

import (
	"context"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"ipa-loader/app/internal/apple"
	"ipa-loader/app/internal/platform"
	"testing"
)

func TestLoaderButtonDoesNotRequireSelectingAnIPA(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	updates := make(chan func(), 8)
	fyne.SetCurrentApp(&accountTestApp{a, &accountTestDriver{a.Driver(), updates}})
	w := a.NewWindow("bootstrap")
	defer w.Close()
	called := make(chan struct{}, 1)
	release := make(chan struct{})
	s := New(w, Services{Bootstrap: func(ctx context.Context, session *apple.Session, team string, d platform.Device, p func(platform.Progress)) (platform.Result, error) {
		if team != "TEST" || d.ID != "device" {
			t.Error("wrong bootstrap selection")
		}
		called <- struct{}{}
		<-release
		return platform.Result{Installed: true, CompletionMessage: "Setup complete"}, nil
	}})
	s.showAccount(&apple.Session{Username: "test@example.invalid"}, []apple.Team{{ID: "TEST"}})
	if !s.loader.Disabled() {
		t.Fatal("loader enabled without a device")
	}
	s.devices = []platform.Device{{ID: "device", Name: "Test"}}
	s.device.Options = []string{"Test"}
	s.device.SetSelectedIndex(0)
	if s.loader.Disabled() || !s.install.Disabled() {
		t.Fatal("bootstrap readiness incorrectly depends on an IPA")
	}
	s.loader.OnTapped()
	<-called
	if !s.busy || !s.loader.Disabled() {
		t.Fatal("bootstrap allowed concurrent operations")
	}
	s.loader.OnTapped()
	close(release)
	waitAccountUpdate(t, updates)
	if s.selected != nil || s.busy || s.status.Text != "Setup complete" || len(called) != 0 {
		t.Fatal("bootstrap changed selection or left incorrect state")
	}
}
