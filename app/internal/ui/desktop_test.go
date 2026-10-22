package ui

import (
	"context"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"ipa-loader/app/internal/apple"
	"ipa-loader/app/internal/platform"
)

func TestDesktopTasksHaveSeparatePrimaryActions(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	w := a.NewWindow("tasks")
	defer w.Close()
	s := NewPreview(w, "empty")
	if s.installAction.Objects[0] != s.install || s.selected != nil {
		t.Fatal("unexpected initial install task")
	}
	s.taskTabs.Select(s.setupTask)
	if s.installAction.Objects[0] != s.loader || s.loader.Disabled() || !strings.Contains(s.status.Text, "set up") {
		t.Fatal("setup still competes with IPA installation or needs an IPA")
	}
	s.taskTabs.SelectIndex(0)
	if s.installAction.Objects[0] != s.install || !s.install.Disabled() {
		t.Fatal("returning to install lost its own readiness")
	}
}

func TestSavedAccountSelectionWaitsForContinue(t *testing.T) {
	s, store, done := accountScreen(t, false)
	s.accountsLoaded = true
	snapshot, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	s.applySavedAccounts(snapshot)
	s.savedSelector.SetSelected("first@example.invalid")
	if s.session != nil || s.busy || s.loginFields.Visible() || !s.continueAccount.Visible() {
		t.Fatal("selecting an account implicitly signed in or displayed competing forms")
	}
	s.continueAccount.OnTapped()
	waitAccountUpdate(t, done)
	if s.session == nil || s.session.Username != "first@example.invalid" {
		t.Fatal("Continue did not validate the selected account")
	}
}

func TestAccountNavigationPreservesWindowSize(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	w := a.NewWindow("stable window")
	defer w.Close()
	s := New(w, Services{})
	w.Resize(fyne.NewSize(720, 640))
	before := w.Canvas().Size()
	s.showAccount(&apple.Session{Username: "account@example.invalid"}, []apple.Team{{ID: "TEAM", Name: "Personal"}})
	s.returnToLogin()
	if w.Canvas().Size() != before {
		t.Fatal("account navigation resized the user's window")
	}
}

func TestDiscoveryRequiresAnExplicitChoiceForMultiplePhones(t *testing.T) {
	s, _, done := accountScreen(t, false)
	s.showAccount(&apple.Session{Username: "account@example.invalid"}, []apple.Team{{ID: "TEAM"}})
	devices := []platform.Device{{ID: "one", UDID: "private-one", Name: "Test iPhone", Transport: "USB"}, {ID: "two", UDID: "private-two", Name: "Test iPhone", Transport: "USB"}}
	s.services.Devices = func(context.Context) ([]platform.Device, error) { return devices, nil }
	s.refreshDevices()
	waitAccountUpdate(t, done)
	if s.device.SelectedIndex() != -1 || s.device.Options[0] == s.device.Options[1] || strings.Contains(strings.Join(s.device.Options, " "), "private-") {
		t.Fatal("discovery guessed a phone, lost ambiguity or exposed hardware IDs")
	}
	s.device.SetSelectedIndex(1)
	devices = []platform.Device{devices[1], devices[0]}
	s.refreshDevices()
	waitAccountUpdate(t, done)
	if s.devices[s.device.SelectedIndex()].ID != "two" {
		t.Fatal("rescanning changed the selected phone when inventory order changed")
	}
}

func TestLastInstallationRetainsItsResult(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	w := a.NewWindow("result")
	defer w.Close()
	s := NewPreview(w, "success")
	result := s.operationStatus.Text
	s.setStatus("Loading development certificates…")
	if s.operationStatus.Text != result {
		t.Fatal("another operation replaced the last installation result")
	}
}

func TestCompactDesktopKeepsFileAndInstallActionsReachable(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	a.Settings().SetTheme(NewTheme())
	for _, state := range []string{"empty", "ready", "long", "setup"} {
		w := a.NewWindow(state)
		s := NewPreview(w, state)
		w.Resize(fyne.NewSize(520, 500))
		w.Show()
		s.root.Refresh()
		body := a.Driver().AbsolutePositionForObject(s.installBody)
		if state != "setup" {
			p := a.Driver().AbsolutePositionForObject(s.choose)
			if p.Y+s.choose.Size().Height > body.Y+s.installBody.Size().Height+1 {
				t.Errorf("file button clipped in %s", state)
			}
		}
		primary := s.installAction.Objects[0]
		p := a.Driver().AbsolutePositionForObject(primary)
		if primary.Size().Height < 40 || p.Y+primary.Size().Height > w.Canvas().Size().Height {
			t.Errorf("primary action clipped or squished in %s", state)
		}
		w.Close()
	}
}

func TestAccountMenuMarksCurrentAndProvidesManagement(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	w := a.NewWindow("account menu")
	defer w.Close()
	s := NewPreview(w, "accounts")
	menu := s.accountMenu()
	if len(menu.Items) != 5 || !menu.Items[0].Checked || !menu.Items[0].Disabled || menu.Items[1].Disabled || menu.Items[3].Label != "Add Another Account…" || menu.Items[4].Label != "Manage Saved Accounts…" {
		t.Fatal("account menu lost its current account or clear add/manage actions")
	}
}

func TestRemovingAnotherSavedAccountPreservesCurrentSignIn(t *testing.T) {
	s, store, done := accountScreen(t, false)
	s.Start()
	waitAccountUpdate(t, done)
	waitAccountUpdate(t, done)
	s.removeSavedAccount("first@example.invalid")
	waitAccountUpdate(t, done)
	snapshot, err := store.Load()
	if err != nil || s.session == nil || s.session.Username != "second@example.invalid" || snapshot.Active != "second@example.invalid" || len(snapshot.Sessions) != 1 || !s.installPage.Visible() {
		t.Fatal("removing a different saved account interrupted the current account")
	}
	s.removeSavedAccount("second@example.invalid")
	waitAccountUpdate(t, done)
	snapshot, err = store.Load()
	if err != nil || s.session != nil || len(snapshot.Sessions) != 0 || !s.loginPage.Visible() {
		t.Fatal("removing the current account left it signed in")
	}
}

func TestFailedDesktopSwitchPreservesValidatedAccount(t *testing.T) {
	s, store, done := accountScreen(t, false)
	s.Start()
	waitAccountUpdate(t, done)
	waitAccountUpdate(t, done)
	s.services.Teams = func(context.Context, *apple.Session) ([]apple.Team, error) {
		return nil, &apple.Error{Code: 1100, Message: "Candidate expired"}
	}
	s.switchAccount("first@example.invalid")
	waitAccountUpdate(t, done)
	snapshot, err := store.Load()
	if err != nil || s.session == nil || s.session.Username != "second@example.invalid" || !s.installPage.Visible() || snapshot.Active != "second@example.invalid" {
		t.Fatal("failed switch discarded the validated account")
	}
}

func TestExpiredInstallationOffersDirectSignIn(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	w := a.NewWindow("sign in again")
	defer w.Close()
	s := NewPreview(w, "error")
	if s.operationHeading.Text != "Installation Needs Attention" || !s.operationAccount.Visible() || s.operationDone.Importance == s.operationAccount.Importance {
		t.Fatal("result did not identify the problem and primary next action")
	}
	s.operationAccount.OnTapped()
	if s.session != nil || !s.loginFields.Visible() || s.username.Text != "alex@example.invalid" || !s.loginNeedsPassword {
		t.Fatal("Sign In Again lost the account or hid the password form")
	}
}

func TestExpandedDetailsUseSpaceAndKeepActionsAtBottom(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	a.Settings().SetTheme(NewTheme())
	w := a.NewWindow("details layout")
	defer w.Close()
	s := NewPreview(w, "details")
	w.Resize(fyne.NewSize(520, 480))
	w.Show()
	s.resizeOperation()
	expanded := s.operationDialog.Size().Height
	logEnd := a.Driver().AbsolutePositionForObject(s.activityScroll).Y + s.activityScroll.Size().Height
	buttonTop := a.Driver().AbsolutePositionForObject(s.cancelButton).Y
	if buttonTop-logEnd > 12 || logEnd > buttonTop {
		t.Fatal("unused space separates Details from the action row")
	}
	s.toggleActivity()
	if s.operationDialog.Size().Height >= expanded {
		t.Fatal("collapsed details retained the expanded height")
	}
	for i := 0; i < 30; i++ {
		s.log("A complete signing and upload progress message")
	}
	s.toggleActivity()
	if s.activityScroll.MinSize().Height > 180 || s.operationDialog.Size().Height > w.Canvas().Size().Height {
		t.Fatal("long logs expanded beyond their bounded scroll area")
	}
}

func TestLongResultKeepsRecoveryActionsVisible(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	w := a.NewWindow("long result")
	defer w.Close()
	s := NewPreview(w, "progress")
	w.Resize(fyne.NewSize(520, 480))
	w.Show()
	s.setStatus(strings.Repeat("The server returned additional diagnostic information. ", 60))
	s.setBusy(false)
	s.finishOperation(&apple.Error{Code: 1100, Message: "Expired"})
	s.toggleActivity()
	if s.operationDialog.Size().Height > w.Canvas().Size().Height {
		t.Fatal("long error pushed the result dialog off screen")
	}
	for _, button := range []fyne.CanvasObject{s.operationDone, s.operationAccount} {
		p := a.Driver().AbsolutePositionForObject(button)
		if p.Y < 0 || p.Y+button.Size().Height > w.Canvas().Size().Height {
			t.Fatal("recovery action fell outside the window")
		}
	}
}

func TestChangingTasksUpdatesGuidanceAndPreservesLastResult(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	w := a.NewWindow("task guidance")
	defer w.Close()
	s := NewPreview(w, "success")
	result := s.operationStatus.Text
	s.taskTabs.Select(s.setupTask)
	if !strings.Contains(s.status.Text, "Ready to set up") || s.operationStatus.Text != result || !s.reviewOperation.Visible() {
		t.Fatal("new task kept stale guidance or lost the last installation result")
	}
}
