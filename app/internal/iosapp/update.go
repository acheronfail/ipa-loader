package iosapp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"ipa-loader/app/internal/platform"
)

// Release checks do not acquire the signing/device operation slot or require
// sign-in. Foreground notifications are throttled and failed checks retry sooner.
func (c *Controller) checkUpdate(manual bool) {
	if c.services.CheckUpdate == nil {
		return
	}
	c.mu.Lock()
	if c.state.UpdateChecking || c.state.Operation == "update" && c.state.Busy || !manual && time.Now().Before(c.nextUpdateCheck) {
		c.mu.Unlock()
		return
	}
	c.state.UpdateChecking = true
	c.mu.Unlock()
	c.publish()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	release, err := c.services.CheckUpdate(ctx)
	c.mu.Lock()
	c.state.UpdateChecking = false
	c.state.UpdateCheckFailed = err != nil
	c.state.UpdateCheckedAt = time.Now().Unix()
	c.nextUpdateCheck = time.Now().Add(6 * time.Hour)
	if err != nil {
		c.nextUpdateCheck = time.Now().Add(15 * time.Minute)
		c.state.UpdateMessage = err.Error()
	} else {
		c.update = release
		c.state.UpdateVersion = ""
		c.state.UpdateMessage = "IPA Loader is up to date."
		if release != nil {
			c.state.UpdateVersion = release.Version
			c.state.UpdateMessage = "IPA Loader " + release.Version + " is available. Sign in and connect your local VPN to update. The app may close during installation; reopen it afterward."
		}
	}
	c.mu.Unlock()
	c.publish()
}

func (c *Controller) installUpdate() {
	if c.services.DownloadUpdate == nil || c.services.InstallUpdate == nil || c.services.UpdateTeam == nil {
		return
	}
	ctx, ok := c.begin(true, "update", "IPA Loader")
	if !ok {
		return
	}
	defer func() {
		if c.services.Reload != nil {
			c.services.Reload()
		}
	}()
	session, _ := c.credentials()
	team := c.services.UpdateTeam()
	c.mu.Lock()
	release := c.update
	ownsTeam := false
	for _, t := range c.state.Teams {
		if t.ID == team {
			ownsTeam = true
		}
	}
	c.mu.Unlock()
	if release == nil {
		c.end(ctx, errors.New("Check for an IPA Loader update first."))
		return
	}
	if team == "" || !ownsTeam {
		c.end(ctx, errors.New("Sign in with the Apple Account used to install IPA Loader."))
		return
	}
	c.progress(platform.Progress{Message: "Connecting to this iPhone…"})
	device, err := c.services.Device(ctx)
	if err != nil {
		c.end(ctx, err)
		return
	}
	c.progress(platform.Progress{Message: "Downloading IPA Loader " + release.Version + "…"})
	path, err := c.services.DownloadUpdate(ctx, *release, func(n, total int64) {
		c.progress(platform.Progress{Message: fmt.Sprintf("Downloading IPA Loader %s · %.1f of %.1f MB", release.Version, float64(n)/1e6, float64(total)/1e6)})
	})
	if path != "" {
		defer os.RemoveAll(filepath.Dir(path))
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		c.progress(platform.Progress{Message: "Re-signing IPA Loader " + release.Version + "…"})
		var result platform.Result
		result, err = c.services.InstallUpdate(ctx, session, team, path, device, c.progress)
		if err == nil {
			message := result.CompletionMessage
			if message == "" {
				message = "IPA Loader update submitted. Reopen the app after installation finishes."
			}
			c.progress(platform.Progress{Fraction: 1, Message: message})
		}
	}
	c.end(ctx, err)
}
