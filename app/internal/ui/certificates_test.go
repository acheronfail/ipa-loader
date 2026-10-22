package ui

import (
	"context"
	"errors"
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"ipa-loader/app/internal/apple"
	"ipa-loader/app/internal/ipa"
	"ipa-loader/app/internal/platform"
)

func certificateScreen(t *testing.T) (*Screen, chan func()) {
	t.Helper()
	a := test.NewApp()
	a.Settings().SetTheme(NewTheme())
	done := make(chan func(), 20)
	fyne.SetCurrentApp(&accountTestApp{a, &accountTestDriver{a.Driver(), done}})
	w := a.NewWindow("certificate recovery")
	t.Cleanup(func() {
		for _, open := range a.Driver().AllWindows() {
			if open == w {
				w.Close()
				break
			}
		}
		a.Quit()
	})
	s := New(w, Services{})
	s.showAccount(&apple.Session{Username: "synthetic@example.invalid"}, []apple.Team{{ID: "TEAM1", Name: "Test team"}})
	return s, done
}
func certificateFixtures() []apple.DevelopmentCertificate {
	return []apple.DevelopmentCertificate{
		{Serial: "old-cert", Name: "Older certificate", Kind: "iPhone Developer", SHA256: "old-hash", IssuedAt: time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)},
		{Serial: "chosen-cert", Name: "Chosen certificate", Kind: "Apple Development", SHA256: "chosen-hash", IssuedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)},
	}
}

func TestCertificatesAccessibleWithoutSideload(t *testing.T) {
	s, done := certificateScreen(t)
	var listedTeam string
	s.services.DevelopmentCertificates = func(_ context.Context, _ *apple.Session, team string) ([]apple.DevelopmentCertificate, error) {
		listedTeam = team
		return certificateFixtures(), nil
	}
	s.services.RevokeDevelopmentCertificate = func(context.Context, *apple.Session, string, apple.DevelopmentCertificate) error {
		t.Error("opening certificate management must not revoke")
		return nil
	}
	s.showAccount(s.session, []apple.Team{{ID: "TEAM1", Name: "First team"}, {ID: "TEAM2", Name: "Second team"}})
	if !s.manageCertificates.Visible() || !s.manageCertificates.Disabled() {
		t.Fatal("certificate action should wait for team selection")
	}
	s.manageDevelopmentCertificates()
	if s.certificateRecovery != nil {
		t.Fatal("opened certificates without a selected team")
	}
	s.team.SetSelectedIndex(1)
	if s.manageCertificates.Disabled() || s.selected != nil || s.device.SelectedIndex() >= 0 {
		t.Fatal("certificate management should only require a signed-in team")
	}
	test.Tap(s.manageCertificates)
	if !s.manageCertificates.Disabled() {
		t.Fatal("certificate action remained enabled during lookup")
	}
	waitAccountUpdate(t, done)
	r := s.certificateRecovery
	if listedTeam != "TEAM2" || r == nil || r.manager == nil || r.quotaReached {
		t.Fatal("certificate action did not open management for the selected team")
	}
	r.manager.Hide()
	if !s.manageCertificates.Visible() || s.manageCertificates.Disabled() {
		t.Fatal("closing management removed access")
	}
	s.returnToLogin()
	if s.manageCertificates.Visible() || s.certificateRecovery != nil {
		t.Fatal("certificate management survived sign-out")
	}
}

func TestCertificateManagementWithoutQuotaUsesGeneralMessages(t *testing.T) {
	for _, empty := range []bool{true, false} {
		t.Run(fmt.Sprintf("empty=%t", empty), func(t *testing.T) {
			s, done := certificateScreen(t)
			s.services.DevelopmentCertificates = func(context.Context, *apple.Session, string) ([]apple.DevelopmentCertificate, error) {
				if empty {
					return nil, nil
				}
				return certificateFixtures(), nil
			}
			s.services.RevokeDevelopmentCertificate = func(context.Context, *apple.Session, string, apple.DevelopmentCertificate) error { return nil }
			s.readiness()
			test.Tap(s.manageCertificates)
			waitAccountUpdate(t, done)
			if empty {
				if s.status.Text != "This developer team has no active development certificates." {
					t.Fatal("empty team suggested retrying an installation", s.status.Text)
				}
			} else {
				r := s.certificateRecovery
				r.selector.SetSelectedIndex(0)
				s.confirmCertificateRevocation(r)
				r.confirmation.Confirm()
				waitAccountUpdate(t, done)
				if s.status.Text != "Certificate revoked." {
					t.Fatal("manual revocation suggested retrying an installation", s.status.Text)
				}
			}
			if !s.manageCertificates.Visible() || s.manageCertificates.Disabled() {
				t.Fatal("certificate management no longer accessible")
			}
		})
	}
}
func TestCertificateQuotaOffersActionWithoutRevoking(t *testing.T) {
	s, done := certificateScreen(t)
	s.selected = &ipa.Info{Path: "synthetic.ipa"}
	s.devices = []platform.Device{{UDID: "synthetic-device", Name: "Test iPhone", Transport: "USB"}}
	s.device.Options = []string{"Test iPhone"}
	s.device.SetSelectedIndex(0)
	listCalls, revokeCalls := 0, 0
	s.services.DevelopmentCertificates = func(context.Context, *apple.Session, string) ([]apple.DevelopmentCertificate, error) {
		listCalls++
		return certificateFixtures(), nil
	}
	s.services.RevokeDevelopmentCertificate = func(context.Context, *apple.Session, string, apple.DevelopmentCertificate) error {
		revokeCalls++
		return nil
	}
	s.services.Sideload = func(context.Context, *apple.Session, string, string, platform.Device, func(platform.Progress)) (platform.Result, error) {
		return platform.Result{}, fmt.Errorf("wrapped failure: %w", &apple.Error{Code: 7460})
	}
	s.sideload()
	waitAccountUpdate(t, done)
	if !s.manageCertificates.Visible() || listCalls != 0 || revokeCalls != 0 {
		t.Fatal("quota error performed unsolicited certificate operations")
	}
	s.returnToLogin()
	if s.manageCertificates.Visible() || s.certificateRecovery != nil {
		t.Fatal("quota action survived sign-out")
	}
}
func TestCertificateRevocationRequiresSelectionAndNamedConfirmation(t *testing.T) {
	s, done := certificateScreen(t)
	calls := make(chan apple.DevelopmentCertificate, 4)
	s.services.DevelopmentCertificates = func(context.Context, *apple.Session, string) ([]apple.DevelopmentCertificate, error) {
		return certificateFixtures(), nil
	}
	s.services.RevokeDevelopmentCertificate = func(_ context.Context, session *apple.Session, team string, c apple.DevelopmentCertificate) error {
		if session != s.session || team != "TEAM1" {
			return errors.New("changed account or team")
		}
		calls <- c
		return nil
	}
	s.showCertificateQuota(s.session, "TEAM1")
	s.manageDevelopmentCertificates()
	waitAccountUpdate(t, done)
	r := s.certificateRecovery
	if r.selector.SelectedIndex() != -1 || !r.revoke.Disabled() {
		t.Fatal("certificate selected by default")
	}
	s.confirmCertificateRevocation(r)
	if r.confirmation != nil || len(calls) != 0 {
		t.Fatal("unselected certificate could be revoked")
	}
	r.selector.SetSelectedIndex(1)
	if r.revoke.Disabled() {
		t.Fatal("explicit selection did not enable review")
	}
	s.confirmCertificateRevocation(r)
	if r.confirmation == nil || len(calls) != 0 {
		t.Fatal("review skipped explicit confirmation")
	}
	cancelled := r.confirmation
	cancelled.Hide()
	cancelled.Confirm() // A closed confirmation cannot be replayed.
	if len(calls) != 0 || s.busy {
		t.Fatal("cancelled confirmation changed the account")
	}
	s.manageDevelopmentCertificates()
	waitAccountUpdate(t, done)
	r.selector.SetSelectedIndex(1)
	s.confirmCertificateRevocation(r)
	confirmed := r.confirmation
	confirmed.Confirm()
	select {
	case got := <-calls:
		if got != certificateFixtures()[1] {
			t.Fatal("revoked a different certificate", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("confirmed request was not submitted")
	}
	waitAccountUpdate(t, done)
	confirmed.Confirm()
	if len(calls) != 0 || !s.manageCertificates.Visible() || !strings.Contains(s.status.Text, "Click Install App") {
		t.Fatal("revocation did not finish safely or was repeated")
	}
}
func TestCertificateLookupCancellationAndStaleAccountAreIgnored(t *testing.T) {
	for _, mode := range []string{"cancel", "account", "close"} {
		t.Run(mode, func(t *testing.T) {
			s, done := certificateScreen(t)
			started := make(chan struct{})
			release := make(chan struct{})
			s.services.DevelopmentCertificates = func(ctx context.Context, _ *apple.Session, _ string) ([]apple.DevelopmentCertificate, error) {
				close(started)
				<-release
				return certificateFixtures(), nil
			}
			revoked := false
			s.services.RevokeDevelopmentCertificate = func(context.Context, *apple.Session, string, apple.DevelopmentCertificate) error {
				revoked = true
				return nil
			}
			s.showCertificateQuota(s.session, "TEAM1")
			s.manageDevelopmentCertificates()
			<-started
			if mode == "account" {
				s.showAccount(&apple.Session{Username: "other@example.invalid"}, []apple.Team{{ID: "OTHER"}})
			} else if mode == "close" {
				s.Window.Close()
			} else {
				s.cancel()
			}
			close(release)
			waitAccountUpdate(t, done)
			if s.busy || revoked || (s.certificateRecovery != nil && s.certificateRecovery.manager != nil) {
				t.Fatal("cancelled/stale lookup opened management or changed account")
			}
		})
	}
}
func TestCertificateConfirmationCannotCrossTeamsAndUncertainRevocationDoesNotRetry(t *testing.T) {
	s, done := certificateScreen(t)
	calls := make(chan string, 3)
	s.services.DevelopmentCertificates = func(context.Context, *apple.Session, string) ([]apple.DevelopmentCertificate, error) {
		return certificateFixtures(), nil
	}
	s.services.RevokeDevelopmentCertificate = func(_ context.Context, _ *apple.Session, team string, _ apple.DevelopmentCertificate) error {
		calls <- team
		return context.DeadlineExceeded
	}
	s.showCertificateQuota(s.session, "TEAM1")
	s.manageDevelopmentCertificates()
	waitAccountUpdate(t, done)
	r := s.certificateRecovery
	r.selector.SetSelectedIndex(0)
	s.confirmCertificateRevocation(r)
	stale := r.confirmation
	s.showAccount(s.session, []apple.Team{{ID: "OTHER", Name: "Other team"}})
	stale.Confirm()
	if len(calls) != 0 {
		t.Fatal("old confirmation revoked under a changed team")
	}
	s.showCertificateQuota(s.session, "OTHER")
	s.manageDevelopmentCertificates()
	waitAccountUpdate(t, done)
	r = s.certificateRecovery
	r.selector.SetSelectedIndex(1)
	s.confirmCertificateRevocation(r)
	r.confirmation.Confirm()
	waitAccountUpdate(t, done)
	if len(calls) != 1 || !s.manageCertificates.Visible() || !strings.Contains(s.status.Text, "not confirmed") {
		t.Fatal("uncertain revocation retried or hid refresh action")
	}
}

// Explicit synthetic-only visual review. No account or device operations run.
func TestCertificateReviewSnapshots(t *testing.T) {
	dir := os.Getenv("IPA_LOADER_UI_REVIEW")
	if dir == "" {
		t.Skip("optional certificate dialog review")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	s, done := certificateScreen(t)
	s.Window.Resize(fyne.NewSize(600, 500))
	s.Window.Show()
	s.services.DevelopmentCertificates = func(context.Context, *apple.Session, string) ([]apple.DevelopmentCertificate, error) {
		return certificateFixtures(), nil
	}
	s.services.RevokeDevelopmentCertificate = func(context.Context, *apple.Session, string, apple.DevelopmentCertificate) error {
		t.Error("snapshot must never revoke")
		return nil
	}
	s.showCertificateQuota(s.session, "TEAM1")
	s.manageDevelopmentCertificates()
	waitAccountUpdate(t, done)
	r := s.certificateRecovery
	r.selector.SetSelectedIndex(1)
	capture := func(name string) {
		t.Helper()
		s.root.Refresh()
		file, err := os.Create(filepath.Join(dir, name+".png"))
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if err = png.Encode(file, s.Window.Canvas().Capture()); err != nil {
			t.Fatal(err)
		}
	}
	capture("certificates-manager")
	s.confirmCertificateRevocation(r)
	capture("certificates-confirmation")
	r.confirmation.Hide()
}
