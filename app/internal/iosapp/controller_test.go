package iosapp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ipa-loader/app/internal/accounts"
	"ipa-loader/app/internal/apple"
	"ipa-loader/app/internal/ipa"
	"ipa-loader/app/internal/platform"
)

type vault struct{ data []byte }

func (v *vault) Read() ([]byte, error)   { return append([]byte(nil), v.data...), nil }
func (v *vault) Write(data []byte) error { v.data = append([]byte(nil), data...); return nil }
func signedInController(s Services) *Controller {
	c := New(s)
	c.session = &apple.Session{Username: "owner@example.invalid", Token: "private-token"}
	c.state.Authenticated = true
	c.state.Username = c.session.Username
	c.state.TeamID = "DEFAULT"
	c.state.Teams = []apple.Team{{ID: "DEFAULT"}, {ID: "ORIGINAL"}}
	return c
}
func TestRefreshStaysInAppsAndUsesOriginalTeam(t *testing.T) {
	calls, reloads := 0, 0
	c := signedInController(Services{RefreshTeam: func(string) string { return "ORIGINAL" }, Device: func(context.Context) (platform.Device, error) { return platform.Device{UDID: "PHONE"}, nil }, Refresh: func(ctx context.Context, s *apple.Session, team, id string, d platform.Device, p func(platform.Progress)) (platform.Result, error) {
		calls++
		if team != "ORIGINAL" || id != "org.example.app" || d.UDID != "PHONE" {
			t.Fatal("lost app's original identity")
		}
		p(platform.Progress{Fraction: .6, Message: "Applying profiles"})
		return platform.Result{ProfileRefreshed: true, CompletionMessage: "App refreshed. No reinstallation needed."}, nil
	}, Reload: func() { reloads++ }})
	c.Handle(Action{Kind: "refresh", Value: "org.example.app"})
	state := c.Snapshot()
	if state.Busy || state.Failed || calls != 1 || reloads != 1 || state.Operation != "refresh" || state.Target != "org.example.app" || !strings.Contains(state.Message, "No reinstallation") {
		t.Fatalf("unexpected state %+v", state)
	}
	raw, _ := json.Marshal(state)
	if strings.Contains(string(raw), "private-token") {
		t.Fatal("credential leaked into UI snapshot")
	}
}
func TestSignedOutAndBusyActionsCannotMutate(t *testing.T) {
	calls := 0
	c := New(Services{Device: func(context.Context) (platform.Device, error) { calls++; return platform.Device{}, nil }})
	c.Handle(Action{Kind: "refresh", Value: "org.example.app"})
	c.Handle(Action{Kind: "import"})
	if calls != 0 {
		t.Fatal("signed-out action reached device")
	}
	c = signedInController(Services{})
	c.state.Busy = true
	c.Handle(Action{Kind: "signout"})
	c.Handle(Action{Kind: "team", Value: "ORIGINAL"})
	c.Handle(Action{Kind: "refresh", Value: "org.example.app"})
	if c.session == nil || c.state.TeamID != "DEFAULT" {
		t.Fatal("busy account changed")
	}
}
func TestSavedAccountMustValidateBeforeRefresh(t *testing.T) {
	store := accounts.New(&vault{})
	session := &apple.Session{Username: "owner@example.invalid", Token: "secret", DSID: "123", IdentityFP: "identity"}
	if err := store.Save(session); err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	finished := make(chan struct{})
	c := New(Services{Accounts: store, Teams: func(context.Context, *apple.Session) ([]apple.Team, error) {
		close(started)
		<-release
		return nil, &apple.Error{Code: 1100, Message: "Expired"}
	}})
	go func() { c.Handle(Action{Kind: "start"}); close(finished) }()
	<-started
	state := c.Snapshot()
	if state.Authenticated || !state.Busy {
		t.Fatal("saved account enabled before validation")
	}
	c.Handle(Action{Kind: "refresh", Value: "org.example.app"})
	close(release)
	<-finished
	state = c.Snapshot()
	if state.Authenticated || state.Busy || !strings.Contains(state.AccountMessage, "Sign in again") {
		t.Fatal(state)
	}
}
func TestCancelAndDuplicateRefresh(t *testing.T) {
	started, finished := make(chan struct{}), make(chan struct{})
	calls := 0
	c := signedInController(Services{Device: func(context.Context) (platform.Device, error) { return platform.Device{}, nil }, Refresh: func(ctx context.Context, _ *apple.Session, _, _ string, _ platform.Device, _ func(platform.Progress)) (platform.Result, error) {
		calls++
		close(started)
		<-ctx.Done()
		return platform.Result{}, ctx.Err()
	}})
	go func() { c.Handle(Action{Kind: "refresh", Value: "org.example.app"}); close(finished) }()
	<-started
	c.Handle(Action{Kind: "refresh", Value: "org.example.app"})
	c.Handle(Action{Kind: "cancel"})
	<-finished
	if calls != 1 || c.Snapshot().Busy || c.Snapshot().Failed || !c.Snapshot().Cancelled {
		t.Fatal("duplicate refresh or cancellation failed")
	}
}
func importedFixture(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "fixtures", "ipas", "ipa-loader-framework-v1-unsigned.ipa"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "picked", "selected.ipa")
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestNativeImportConfirmsAndInstallsExactlyOnce(t *testing.T) {
	path := importedFixture(t)
	confirms, installs := 0, 0
	c := signedInController(Services{ChooseIPA: func() (string, error) { return path, nil }, ConfirmIPA: func(info *ipa.Info) (bool, bool, error) {
		confirms++
		if info.BundleID != "org.ipaloader.frameworktest" {
			t.Fatal("incorrect confirmation metadata")
		}
		return true, false, nil
	}, Device: func(context.Context) (platform.Device, error) { return platform.Device{}, nil }, Install: func(_ context.Context, _ *apple.Session, _, input string, _ platform.Device, _ func(platform.Progress)) (platform.Result, error) {
		installs++
		if input != path {
			t.Fatal("wrong IPA")
		}
		return platform.Result{Installed: true}, nil
	}})
	c.Handle(Action{Kind: "import"})
	if confirms != 1 || installs != 1 || c.Snapshot().Failed || c.Snapshot().Message != "App installed." {
		t.Fatal(c.Snapshot())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("temporary import not cleaned up")
	}
}
func TestFallbackRequiresMatchingOriginalIPA(t *testing.T) {
	path := importedFixture(t)
	installs := 0
	c := signedInController(Services{Device: func(context.Context) (platform.Device, error) { return platform.Device{}, nil }, Refresh: func(context.Context, *apple.Session, string, string, platform.Device, func(platform.Progress)) (platform.Result, error) {
		return platform.Result{}, platform.ErrRefreshNeedsIPA
	}, ConfirmFallback: func(string) bool { return true }, ChooseIPA: func() (string, error) { return path, nil }, Install: func(context.Context, *apple.Session, string, string, platform.Device, func(platform.Progress)) (platform.Result, error) {
		installs++
		return platform.Result{}, nil
	}})
	c.Handle(Action{Kind: "refresh", Value: "org.ipaloader.frameworktest.unrelated"})
	if installs != 0 || !c.Snapshot().Failed || !strings.Contains(c.Snapshot().Message, "original IPA") {
		t.Fatal("unrelated IPA replaced requested app")
	}
}
func TestExpiredAccountDisablesAllSigningActions(t *testing.T) {
	c := signedInController(Services{Device: func(context.Context) (platform.Device, error) { return platform.Device{}, nil }, Refresh: func(context.Context, *apple.Session, string, string, platform.Device, func(platform.Progress)) (platform.Result, error) {
		return platform.Result{}, &apple.Error{Code: 1100, Message: "Sign in again"}
	}})
	c.Handle(Action{Kind: "refresh", Value: "org.example.app"})
	if c.Snapshot().Authenticated || c.session != nil {
		t.Fatal("expired account left signing enabled")
	}
}
func TestUnconfirmedRefreshDoesNotLaunchFullSigning(t *testing.T) {
	c := signedInController(Services{Device: func(context.Context) (platform.Device, error) { return platform.Device{}, nil }, Refresh: func(context.Context, *apple.Session, string, string, platform.Device, func(platform.Progress)) (platform.Result, error) {
		return platform.Result{}, errors.New("Profile refresh was not confirmed")
	}, Install: func(context.Context, *apple.Session, string, string, platform.Device, func(platform.Progress)) (platform.Result, error) {
		t.Fatal("uncertain operation triggered reinstall")
		return platform.Result{}, nil
	}})
	c.Handle(Action{Kind: "refresh", Value: "org.example.app"})
	if !c.Snapshot().Failed {
		t.Fatal("uncertain refresh reported success")
	}
}

func TestSuccessfulLoginRemainsAuthenticatedAfterOperationEnds(t *testing.T) {
	c := New(Services{Login: func(context.Context, string, string, func(apple.Challenge) (string, error)) (*apple.Session, error) {
		return &apple.Session{Username: "owner@example.invalid", Token: "secret"}, nil
	}, Teams: func(context.Context, *apple.Session) ([]apple.Team, error) {
		return []apple.Team{{ID: "TEAM", AppIDsUnlimited: true}}, nil
	}})
	c.Handle(Action{Kind: "login", Username: "owner@example.invalid", Password: "test-password"})
	s := c.Snapshot()
	if !s.Authenticated || s.Busy || s.TeamID != "TEAM" || s.Quota != "Unlimited App IDs" {
		t.Fatal("successful authentication was lost", s)
	}
	raw, _ := json.Marshal(s)
	if strings.Contains(string(raw), "test-password") || strings.Contains(string(raw), "secret") {
		t.Fatal("auth data leaked")
	}
}
func TestCanceledValidationCannotEnableSigning(t *testing.T) {
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	c := New(Services{Login: func(context.Context, string, string, func(apple.Challenge) (string, error)) (*apple.Session, error) {
		return &apple.Session{Username: "owner@example.invalid"}, nil
	}, Teams: func(context.Context, *apple.Session) ([]apple.Team, error) {
		close(started)
		<-release
		return []apple.Team{{ID: "TEAM"}}, nil
	}})
	go func() {
		c.Handle(Action{Kind: "login", Username: "owner@example.invalid", Password: "test"})
		close(finished)
	}()
	<-started
	c.Handle(Action{Kind: "cancel"})
	close(release)
	<-finished
	if c.Snapshot().Authenticated || c.Snapshot().Busy {
		t.Fatal("cancelled validation enabled signing")
	}
}

func TestCancelImportReviewDoesNotConnectOrInstall(t *testing.T) {
	path := importedFixture(t)
	c := signedInController(Services{ChooseIPA: func() (string, error) { return path, nil }, ConfirmIPA: func(*ipa.Info) (bool, bool, error) { return false, false, nil }, Device: func(context.Context) (platform.Device, error) {
		t.Fatal("cancelled import connected to device")
		return platform.Device{}, nil
	}})
	c.Handle(Action{Kind: "import"})
	if c.Snapshot().Busy {
		t.Fatal("cancelled review left operation busy")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("cancelled import was not removed")
	}
}

func TestCancelCertificateLookupKeepsValidatedAccount(t *testing.T) {
	started, finished := make(chan struct{}), make(chan struct{})
	c := signedInController(Services{Certificates: func(ctx context.Context, _ *apple.Session, _ string) ([]apple.DevelopmentCertificate, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}})
	go func() { c.Handle(Action{Kind: "certificates"}); close(finished) }()
	<-started
	c.Handle(Action{Kind: "cancel"})
	<-finished
	if !c.Snapshot().Authenticated || c.Snapshot().Busy {
		t.Fatal("cancelling settings invalidated the account")
	}
}

func TestRefreshAllMatchesAccountAndTeamsAndRunsSelfLast(t *testing.T) {
	var ids []string
	c := signedInController(Services{Device: func(context.Context) (platform.Device, error) { return platform.Device{}, nil }, Refresh: func(_ context.Context, _ *apple.Session, team, id string, _ platform.Device, p func(platform.Progress)) (platform.Result, error) {
		ids = append(ids, id)
		if team != "ORIGINAL" {
			t.Fatal("lost original team")
		}
		p(platform.Progress{Fraction: 0.5, Message: "Checking"})
		return platform.Result{CompletionMessage: "Current"}, nil
	}})
	c.UpdateApps([]platform.IOSApp{
		{BundleID: "self", Name: "IPA Loader", Account: "owner@example.invalid", Team: "ORIGINAL", CanRefresh: true, Self: true},
		{BundleID: "app", Name: "App", Account: "OWNER@example.invalid", Team: "ORIGINAL", CanRefresh: true},
		{BundleID: "other-account", Account: "other@example.invalid", Team: "ORIGINAL", CanRefresh: true},
		{BundleID: "unknown", Team: "ORIGINAL", CanRefresh: true},
		{BundleID: "other-team", Account: "owner@example.invalid", Team: "OTHER", CanRefresh: true},
	})
	if c.Snapshot().EligibleRefreshes != 2 {
		t.Fatal("incorrect batch eligibility")
	}
	c.Handle(Action{Kind: "refreshall"})
	if strings.Join(ids, ",") != "app,self" || c.Snapshot().Busy || c.Snapshot().Failed || len(c.Snapshot().Results) != 2 {
		t.Fatalf("unexpected batch: %v %+v", ids, c.Snapshot())
	}
}
func TestRefreshAllRetainsFailuresAndStopsOnExpiredSession(t *testing.T) {
	calls := 0
	c := signedInController(Services{Device: func(context.Context) (platform.Device, error) { return platform.Device{}, nil }, Refresh: func(context.Context, *apple.Session, string, string, platform.Device, func(platform.Progress)) (platform.Result, error) {
		calls++
		if calls == 1 {
			return platform.Result{}, platform.ErrRefreshNeedsIPA
		}
		return platform.Result{}, &apple.Error{Code: 1100, Message: "Expired"}
	}})
	for _, id := range []string{"a", "b", "c"} {
		c.apps = append(c.apps, platform.IOSApp{BundleID: id, Name: id, Account: "owner@example.invalid", Team: "DEFAULT", CanRefresh: true})
	}
	c.Handle(Action{Kind: "refreshall"})
	if calls != 2 || c.Snapshot().Authenticated || !c.Snapshot().Failed {
		t.Fatalf("batch continued after invalid session: %+v", c.Snapshot())
	}
	if !strings.Contains(strings.Join(c.Snapshot().Logs, " "), platform.ErrRefreshNeedsIPA.Error()) {
		t.Fatal("missing per-app failure")
	}
}
func TestVPNOffGatesMutationsAndToggleUsesActualState(t *testing.T) {
	connected := false
	calls := 0
	c := signedInController(Services{VPNState: func() (bool, bool) { return true, connected }, SetVPN: func(on bool) error { connected = on; return nil }, Device: func(context.Context) (platform.Device, error) {
		calls++
		return platform.Device{}, errors.New("device probe")
	}})
	c.Handle(Action{Kind: "vpnstatus"})
	for _, kind := range []string{"refresh", "refreshall", "import"} {
		c.Handle(Action{Kind: kind, Value: "app"})
	}
	if calls != 0 {
		t.Fatal("VPN off allowed device mutation")
	}
	c.Handle(Action{Kind: "vpn", Value: "on"})
	if !c.Snapshot().VPNConnected || c.Snapshot().VPNBusy {
		t.Fatal("toggle did not follow actual VPN state")
	}
	c.Handle(Action{Kind: "refresh", Value: "app"})
	if calls != 1 {
		t.Fatal("connected VPN did not enable refresh")
	}
	c.Handle(Action{Kind: "vpn", Value: "off"})
	if c.Snapshot().VPNConnected {
		t.Fatal("VPN state stale after disabling")
	}
}

func TestRepeatedVPNStatusDoesNotPublishUnchangedUI(t *testing.T) {
	publications := 0
	connected := false
	c := New(Services{VPNState: func() (bool, bool) { return true, connected }, Publish: func(State) { publications++ }})
	c.Handle(Action{Kind: "vpnstatus"})
	for i := 0; i < 100; i++ {
		c.Handle(Action{Kind: "vpnstatus"})
	}
	if publications != 1 {
		t.Fatalf("unchanged VPN republished UI %d times", publications)
	}
	connected = true
	c.Handle(Action{Kind: "vpnstatus"})
	if publications != 2 || !c.Snapshot().VPNConnected {
		t.Fatal("actual VPN transition was lost")
	}
}

func TestExternalVPNDoesNotGateActionsOrInvokeBuiltinToggle(t *testing.T) {
	deviceCalls, toggleCalls := 0, 0
	c := signedInController(Services{
		VPNState: func() (bool, bool) { return false, false },
		SetVPN:   func(bool) error { toggleCalls++; return errors.New("unexpected VPN control") },
		Device: func(context.Context) (platform.Device, error) {
			deviceCalls++
			return platform.Device{}, errors.New("device probe")
		},
	})
	c.Handle(Action{Kind: "vpnstatus"})
	c.Handle(Action{Kind: "vpn", Value: "on"})
	c.Handle(Action{Kind: "vpn", Value: "off"})
	c.Handle(Action{Kind: "refresh", Value: "app"})
	if deviceCalls != 1 || toggleCalls != 0 {
		t.Fatalf("external VPN invoked built-in controls or blocked refresh: device=%d toggle=%d", deviceCalls, toggleCalls)
	}
	if state := c.Snapshot(); state.VPNAvailable || state.VPNBusy || state.VPNMessage != "" {
		t.Fatalf("external VPN acquired built-in state: %+v", state)
	}
}

func TestImportRetainsIPAOnlyWhenChosen(t *testing.T) {
	for _, retain := range []bool{false, true} {
		t.Run(map[bool]string{false: "discard", true: "keep"}[retain], func(t *testing.T) {
			path := importedFixture(t)
			installed := false
			c := signedInController(Services{ChooseIPA: func() (string, error) { return path, nil }, ConfirmIPA: func(*ipa.Info) (bool, bool, error) { return true, retain, nil }, Device: func(context.Context) (platform.Device, error) { return platform.Device{}, nil }, Install: func(ctx context.Context, _ *apple.Session, _, _ string, _ platform.Device, _ func(platform.Progress)) (platform.Result, error) {
				installed = true
				if platform.IOSPackageRetention(ctx) != retain {
					t.Fatal("lost retention choice")
				}
				return platform.Result{Installed: true}, nil
			}})
			c.Handle(Action{Kind: "import"})
			if !installed || c.Snapshot().Failed {
				t.Fatal(c.Snapshot())
			}
		})
	}
}
func TestEmptyFilePickerCancelsWithoutFailure(t *testing.T) {
	c := signedInController(Services{ChooseIPA: func() (string, error) { return "", nil }})
	c.Handle(Action{Kind: "import"})
	s := c.Snapshot()
	if s.Busy || s.Failed || !s.Cancelled || s.Message != "" {
		t.Fatal(s)
	}
}
func TestAccountRemovalAndSignOutPreserveOtherSavedAccounts(t *testing.T) {
	store := accounts.New(&vault{})
	owner := &apple.Session{Username: "owner@example.invalid", Token: "token", DSID: "1", IdentityFP: "id"}
	other := &apple.Session{Username: "other@example.invalid", Token: "token", DSID: "2", IdentityFP: "id"}
	if err := store.Save(owner); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(other); err != nil {
		t.Fatal(err)
	}
	_ = store.Select(owner.Username)
	c := signedInController(Services{Accounts: store})
	_ = c.readSaved()
	c.Handle(Action{Kind: "forget", Value: other.Username})
	if !c.Snapshot().Authenticated || len(c.Snapshot().Accounts) != 1 {
		t.Fatal("removing another account signed out current account")
	}
	c.Handle(Action{Kind: "signout"})
	saved, _ := store.Load()
	if saved.Active != "" || len(saved.Sessions) != 1 || c.Snapshot().Authenticated {
		t.Fatal("sign out did not persist or forgot sign-in")
	}
	c = signedInController(Services{Accounts: store})
	_ = c.readSaved()
	c.Handle(Action{Kind: "forget", Value: owner.Username})
	saved, _ = store.Load()
	if c.Snapshot().Authenticated || len(saved.Sessions) != 0 {
		t.Fatal("removed current account stayed active")
	}
}
func TestFailedAccountSwitchKeepsValidatedAccount(t *testing.T) {
	c := signedInController(Services{Teams: func(context.Context, *apple.Session) ([]apple.Team, error) {
		return nil, &apple.Error{Code: 1100, Message: "expired candidate"}
	}})
	c.saved = []*apple.Session{{Username: "other@example.invalid"}}
	c.Handle(Action{Kind: "resume", Value: "other@example.invalid"})
	if !c.Snapshot().Authenticated || c.Snapshot().Username != "owner@example.invalid" {
		t.Fatal("failed switch invalidated current account")
	}
}

func TestSuccessfulAccountSwitchClearsPreviousCertificates(t *testing.T) {
	c := signedInController(Services{Teams: func(context.Context, *apple.Session) ([]apple.Team, error) {
		return []apple.Team{{ID: "OTHER"}}, nil
	}})
	old := apple.DevelopmentCertificate{SHA256: "old-account-certificate"}
	c.certificates = []apple.DevelopmentCertificate{old}
	c.state.Certificates = []apple.DevelopmentCertificate{old}
	if err := c.validate(context.Background(), &apple.Session{Username: "other@example.invalid"}); err != nil {
		t.Fatal(err)
	}
	if c.Snapshot().Username != "other@example.invalid" || len(c.Snapshot().Certificates) != 0 || len(c.certificates) != 0 {
		t.Fatal("account switch retained another account's certificates")
	}
}
