package ui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"ipa-loader/app/internal/accounts"
	"ipa-loader/app/internal/apple"
)

type testVault struct {
	data       []byte
	writeError error
}

func (v *testVault) Read() ([]byte, error) { return append([]byte(nil), v.data...), nil }
func (v *testVault) Write(data []byte) error {
	if v.writeError != nil {
		return v.writeError
	}
	v.data = append([]byte(nil), data...)
	return nil
}

type accountTestDriver struct {
	fyne.Driver
	done chan func()
}

func (d *accountTestDriver) DoFromGoroutine(fn func(), wait bool) {
	d.done <- fn
}

type accountTestApp struct {
	fyne.App
	driver *accountTestDriver
}

func (a *accountTestApp) Driver() fyne.Driver { return a.driver }

func accountScreen(t *testing.T, expired bool) (*Screen, *accounts.Store, chan func()) {
	t.Helper()
	a := test.NewApp()
	done := make(chan func(), 20)
	fyne.SetCurrentApp(&accountTestApp{a, &accountTestDriver{a.Driver(), done}})
	w := a.NewWindow("saved accounts")
	t.Cleanup(func() { w.Close(); a.Quit() })
	store := accounts.New(&testVault{})
	for _, name := range []string{"first@example.invalid", "second@example.invalid"} {
		if err := store.Save(&apple.Session{Username: name, DSID: "synthetic-dsid", Token: "synthetic-token", IdentityFP: "synthetic-fingerprint"}); err != nil {
			t.Fatal(err)
		}
	}
	s := New(w, Services{Accounts: store, Teams: func(ctx context.Context, session *apple.Session) ([]apple.Team, error) {
		if expired {
			return nil, &apple.Error{Code: 1100, Message: "Session expired"}
		}
		return []apple.Team{{ID: "TEST", Name: session.Username, LimitKnown: true, AppIDLimit: 10}}, nil
	}})
	return s, store, done
}

func waitAccountUpdate(t *testing.T, done <-chan func()) {
	t.Helper()
	select {
	case fn := <-done:
		fn()
	case <-time.After(5 * time.Second):
		t.Fatal("account operation did not finish")
	}
}

func TestAllowanceRefreshDoesNotOverwriteSwitchedAccountOrNewerInstall(t *testing.T) {
	s, _, done := accountScreen(t, false)
	s.services.Teams = func(context.Context, *apple.Session) ([]apple.Team, error) {
		return []apple.Team{{ID: "TEST", LimitKnown: true, AppIDLimit: 10, AvailabilityKnown: true, AppIDsAvailable: 4}}, nil
	}
	first := &apple.Session{Username: "first@example.invalid"}
	second := &apple.Session{Username: "second@example.invalid"}
	s.showAccount(first, []apple.Team{{ID: "TEST", LimitKnown: true, AppIDLimit: 10}})
	s.refreshAllowance(first)
	waitAccountUpdate(t, done)
	if s.accountQuota.Text != "4 of 10 App IDs available" {
		t.Fatal("confirmed allowance was not refreshed")
	}
	s.refreshAllowance(first)
	s.showAccount(second, []apple.Team{{ID: "TEST", LimitKnown: true, AppIDLimit: 10, AvailabilityKnown: true, AppIDsAvailable: 3}})
	waitAccountUpdate(t, done)
	if s.accountQuota.Text != "3 of 10 App IDs available" {
		t.Fatal("old account's quota overwrote current account")
	}
	s.refreshAllowance(second)
	s.allowanceGeneration++ // A newer installation began before this response.
	waitAccountUpdate(t, done)
	if s.accountQuota.Text != "3 of 10 App IDs available" {
		t.Fatal("stale pre-install response overwrote allowance")
	}
}

func TestSavedAccountRestoresAndSwitches(t *testing.T) {
	s, store, done := accountScreen(t, false)
	s.Start()
	waitAccountUpdate(t, done) // Keychain snapshot loaded.
	waitAccountUpdate(t, done) // Last-used session validated.
	if s.session == nil || s.session.Username != "second@example.invalid" || !s.installPage.Visible() {
		t.Fatal("last-used account was not restored")
	}
	s.switchAccount("first@example.invalid")
	waitAccountUpdate(t, done)
	if s.session == nil || s.session.Username != "first@example.invalid" || s.teams[0].Name != "first@example.invalid" {
		t.Fatal("account or team was not switched")
	}
	state, err := store.Load()
	if err != nil || state.Active != "first@example.invalid" {
		t.Fatal("last-used account was not persisted")
	}
	s.switchAccount("Add another account…")
	if s.session != nil || !s.loginPage.Visible() || s.username.Text != "" || s.password.Text != "" {
		t.Fatal("add account did not open a fresh login")
	}
}

func TestExpiredSavedAccountRequiresSignIn(t *testing.T) {
	s, _, done := accountScreen(t, true)
	s.Start()
	waitAccountUpdate(t, done)
	waitAccountUpdate(t, done)
	if s.session != nil || !s.loginPage.Visible() || !s.install.Disabled() || s.username.Text != "second@example.invalid" || s.password.Text != "" || !strings.Contains(s.accountStatus.Text, "Sign in again") {
		t.Fatal("expired session enabled installation or lost login guidance")
	}
}

func TestRemoveSavedAccountAndBusyGuard(t *testing.T) {
	s, store, done := accountScreen(t, false)
	s.Start()
	waitAccountUpdate(t, done)
	waitAccountUpdate(t, done)
	s.setBusy(true)
	s.switchAccount("first@example.invalid")
	if s.session.Username != "second@example.invalid" || !s.switchAccountButton.Disabled() || !s.forgetAccount.Disabled() {
		t.Fatal("account can change during installation")
	}
	s.setBusy(false)
	s.returnToLogin()
	s.forgetSavedAccount()
	waitAccountUpdate(t, done)
	state, err := store.Load()
	if err != nil || len(state.Sessions) != 1 || state.Sessions[0].Username != "first@example.invalid" || s.session != nil {
		t.Fatal("account removal failed")
	}
}

func TestFreshLoginSavesSession(t *testing.T) {
	s, _, done := accountScreen(t, false)
	vault := &testVault{}
	store := accounts.New(vault)
	s.services.Accounts = store
	s.accountsLoaded = true
	s.services.Login = func(context.Context, string, string, func(apple.Challenge) (string, error)) (*apple.Session, error) {
		return &apple.Session{Username: "new@example.invalid", DSID: "new-dsid", Token: "new-token", IdentityFP: "new-fingerprint"}, nil
	}
	s.username.SetText("new@example.invalid")
	s.password.SetText("synthetic-password-not-saved")
	s.login()
	waitAccountUpdate(t, done)
	state, err := store.Load()
	if err != nil || len(state.Sessions) != 1 || state.Active != "new@example.invalid" || s.password.Text != "" {
		t.Fatal("fresh account was not saved")
	}
	if strings.Contains(string(vault.data), "synthetic-password-not-saved") {
		t.Fatal("password persisted")
	}
}

func TestUnsavedLoginDoesNotDisplayAnotherAccount(t *testing.T) {
	s, store, done := accountScreen(t, false)
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	s.applySavedAccounts(state)
	s.accountsLoaded = true
	s.services.Accounts = accounts.New(&testVault{writeError: errors.New("vault locked")})
	s.services.Login = func(context.Context, string, string, func(apple.Challenge) (string, error)) (*apple.Session, error) {
		return &apple.Session{Username: "unsaved@example.invalid", DSID: "new-dsid", Token: "new-token", IdentityFP: "new-fingerprint"}, nil
	}
	s.username.SetText("unsaved@example.invalid")
	s.password.SetText("synthetic")
	s.login()
	waitAccountUpdate(t, done)
	if s.session == nil || s.session.Username != "unsaved@example.invalid" || !strings.Contains(s.accountName.Text, "unsaved@example.invalid") || s.savedSelector.SelectedIndex() != -1 || !s.forgetAccount.Disabled() {
		t.Fatal("unsaved account is mislabeled or unusable")
	}
	state, err = store.Load()
	if err != nil || len(state.Sessions) != 2 {
		t.Fatal("existing accounts were changed")
	}
}

func TestContinueAlreadySelectedAccountAfterGoingBack(t *testing.T) {
	s, _, done := accountScreen(t, false)
	s.Start()
	waitAccountUpdate(t, done)
	waitAccountUpdate(t, done)
	selected := s.savedSelector.Selected
	s.returnToLogin()
	if !s.loginPage.Visible() || !s.continueAccount.Visible() || s.continueAccount.Disabled() || s.savedSelector.Selected != selected {
		t.Fatal("returning to accounts lost the selected account or its continue action")
	}
	s.continueAccount.OnTapped()
	if !s.continueAccount.Disabled() {
		t.Fatal("continue allowed a duplicate reconnect")
	}
	waitAccountUpdate(t, done)
	if s.session == nil || s.session.Username != selected || !s.installPage.Visible() {
		t.Fatal("continue did not resume the already-selected account")
	}
}
