package iosapp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"ipa-loader/app/internal/apple"
	"ipa-loader/app/internal/iosupdate"
	"ipa-loader/app/internal/platform"
)

func TestAutomaticChecksDoNotRequireSignInAndAreThrottled(t *testing.T) {
	calls := 0
	c := New(Services{CheckUpdate: func(context.Context) (*iosupdate.Release, error) {
		calls++
		return &iosupdate.Release{Version: "1.2.0"}, nil
	}})
	c.Handle(Action{Kind: "checkupdateauto"})
	c.Handle(Action{Kind: "checkupdateauto"})
	state := c.Snapshot()
	if calls != 1 || state.UpdateVersion != "1.2.0" || state.Busy || state.Authenticated || state.UpdateChecking {
		t.Fatal(calls, state)
	}
	c.Handle(Action{Kind: "checkupdate"})
	if calls != 2 {
		t.Fatal("manual check was throttled")
	}
	c.services.CheckUpdate = func(context.Context) (*iosupdate.Release, error) { return nil, errors.New("offline") }
	c.Handle(Action{Kind: "checkupdate"})
	state = c.Snapshot()
	if state.UpdateVersion != "1.2.0" || state.UpdateMessage != "offline" || state.Failed {
		t.Fatal("failed check lost known release or interrupted operation", state)
	}
	if time.Until(c.nextUpdateCheck) > 16*time.Minute {
		t.Fatal("failed check did not shorten retry")
	}
}
func TestConcurrentUpdateChecksCoalesce(t *testing.T) {
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	c := New(Services{CheckUpdate: func(context.Context) (*iosupdate.Release, error) { close(started); <-release; return nil, nil }})
	go func() { c.Handle(Action{Kind: "checkupdateauto"}); close(done) }()
	<-started
	c.Handle(Action{Kind: "checkupdate"})
	if !c.Snapshot().UpdateChecking {
		t.Fatal("check status missing")
	}
	close(release)
	<-done
	if c.Snapshot().UpdateChecking {
		t.Fatal("check never finished")
	}
}
func TestUpdateUsesOriginalTeamAndInstallService(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update.ipa")
	os.WriteFile(path, []byte("downloaded"), 0600)
	calls := 0
	c := signedInController(Services{
		UpdateTeam: func() string { return "ORIGINAL" },
		Device:     func(context.Context) (platform.Device, error) { return platform.Device{UDID: "PHONE"}, nil },
		DownloadUpdate: func(ctx context.Context, r iosupdate.Release, p func(int64, int64)) (string, error) {
			if r.Version != "1.2.0" {
				t.Fatal(r)
			}
			p(10, 10)
			return path, nil
		},
		InstallUpdate: func(ctx context.Context, s *apple.Session, team, path string, d platform.Device, p func(platform.Progress)) (platform.Result, error) {
			calls++
			if team != "ORIGINAL" || d.UDID != "PHONE" || s.Username != "owner@example.invalid" {
				t.Fatal(team, d, s.Username)
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatal(err)
			}
			return platform.Result{Installed: true}, nil
		},
	})
	c.update = &iosupdate.Release{Version: "1.2.0"}
	c.Handle(Action{Kind: "update"})
	s := c.Snapshot()
	if calls != 1 || s.Failed || s.Busy || s.Operation != "update" {
		t.Fatal(calls, s)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("temporary download not removed", err)
	}
}
func TestUpdateGatingAndFailure(t *testing.T) {
	for _, reason := range []string{"signedout", "busy", "VPN off", "wrong team", "download failure"} {
		t.Run(reason, func(t *testing.T) {
			installs, downloads := 0, 0
			c := signedInController(Services{
				UpdateTeam: func() string { return "ORIGINAL" },
				Device:     func(context.Context) (platform.Device, error) { return platform.Device{}, nil },
				DownloadUpdate: func(context.Context, iosupdate.Release, func(int64, int64)) (string, error) {
					downloads++
					return "", errors.New("bad digest")
				},
				InstallUpdate: func(context.Context, *apple.Session, string, string, platform.Device, func(platform.Progress)) (platform.Result, error) {
					installs++
					return platform.Result{}, nil
				},
			})
			c.update = &iosupdate.Release{Version: "1.2.0"}
			switch reason {
			case "signedout":
				c.session = nil
				c.state.Authenticated = false
			case "busy":
				c.state.Busy = true
			case "VPN off":
				c.state.VPNAvailable = true
			case "wrong team":
				c.state.Teams = []apple.Team{{ID: "DEFAULT"}}
			}
			c.Handle(Action{Kind: "update"})
			if installs != 0 || (downloads > 0) != (reason == "download failure") {
				t.Fatal(installs, downloads)
			}
		})
	}
}
func TestUpdateCancellationAndDuplicateTap(t *testing.T) {
	started, finished := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	calls := 0
	c := signedInController(Services{
		UpdateTeam: func() string { return "ORIGINAL" },
		Device:     func(context.Context) (platform.Device, error) { return platform.Device{}, nil },
		DownloadUpdate: func(ctx context.Context, _ iosupdate.Release, _ func(int64, int64)) (string, error) {
			mu.Lock()
			calls++
			mu.Unlock()
			close(started)
			<-ctx.Done()
			return "", ctx.Err()
		},
		InstallUpdate: func(context.Context, *apple.Session, string, string, platform.Device, func(platform.Progress)) (platform.Result, error) {
			t.Error("cancelled update installed")
			return platform.Result{}, nil
		},
	})
	c.update = &iosupdate.Release{Version: "1.2.0"}
	go func() { c.Handle(Action{Kind: "update"}); close(finished) }()
	<-started
	c.Handle(Action{Kind: "update"})
	c.Handle(Action{Kind: "cancel"})
	<-finished
	if s := c.Snapshot(); !s.Cancelled || s.Failed || s.Busy {
		t.Fatal(s)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatal(calls)
	}
}

func TestCompletedUpdateChecksPublishPersistentFeedback(t *testing.T) {
	var c *Controller
	var release *iosupdate.Release
	var checkErr error
	c = New(Services{CheckUpdate: func(context.Context) (*iosupdate.Release, error) {
		if !c.Snapshot().UpdateChecking {
			t.Fatal("check did not publish its working state")
		}
		return release, checkErr
	}})
	for _, result := range []struct {
		release *iosupdate.Release
		err     error
		message string
	}{
		{message: "IPA Loader is up to date."},
		{release: &iosupdate.Release{Version: "1.2.0"}},
		{err: errors.New("You are offline."), message: "You are offline."},
		{message: "IPA Loader is up to date."},
	} {
		release, checkErr = result.release, result.err
		before := time.Now().Unix()
		c.Handle(Action{Kind: "checkupdate"})
		state := c.Snapshot()
		if state.UpdateChecking || state.UpdateCheckFailed != (checkErr != nil) || state.UpdateCheckedAt < before || state.UpdateCheckedAt > time.Now().Unix() {
			t.Fatalf("missing completed check feedback: %+v", state)
		}
		if result.message != "" && state.UpdateMessage != result.message {
			t.Fatal(state.UpdateMessage)
		}
	}
}
