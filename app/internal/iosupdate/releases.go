// Package iosupdate downloads published IPA Loader releases. GitHub over HTTPS
// is the release authority; its SHA-256 digest verifies downloaded asset bytes.
package iosupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const latestURL = "https://api.github.com/repos/acheronfail/ipa-loader/releases/latest"
const maxIPA = 512 << 20

var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

type Release struct {
	Version    string
	URL        string
	SHA256     string
	Size       int64
	BuiltinVPN bool
}
type Client struct{ HTTP *http.Client }

func New() *Client { return &Client{HTTP: &http.Client{Timeout: 10 * time.Minute}} }

// Newer compares release versions numerically, rejecting non-release strings.
func Newer(candidate, installed string) (bool, error) {
	if !versionPattern.MatchString(candidate) || !versionPattern.MatchString(installed) {
		return false, errors.New("Could not compare IPA Loader versions")
	}
	a, b := strings.Split(candidate, "."), strings.Split(installed, ".")
	for i := range a {
		// Length-first comparison avoids overflow for arbitrarily large components.
		if len(a[i]) != len(b[i]) {
			return len(a[i]) > len(b[i]), nil
		}
		if a[i] != b[i] {
			return a[i] > b[i], nil
		}
	}
	return false, nil
}
func assetName(builtin bool) string {
	if builtin {
		return "IPA-Loader-Paid-Accounts.ipa"
	}
	return "IPA-Loader-Free-Accounts.ipa"
}
func validRelease(r Release) bool {
	hash, err := hex.DecodeString(r.SHA256)
	return versionPattern.MatchString(r.Version) && err == nil && len(hash) == sha256.Size && r.Size > 0 && r.Size <= maxIPA && r.URL == "https://github.com/acheronfail/ipa-loader/releases/download/v"+r.Version+"/"+assetName(r.BuiltinVPN)
}
func (c *Client) request(ctx context.Context, address string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "IPA-Loader-iOS-Updater")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	// Downloads redirect to GitHub's asset CDN. Never follow a downgrade to HTTP.
	client := *c.HTTP
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || len(via) >= 10 {
			return errors.New("Unsafe update redirect")
		}
		if c.HTTP.CheckRedirect != nil {
			return c.HTTP.CheckRedirect(req, via)
		}
		return nil
	}
	return client.Do(req)
}
func (c *Client) Check(ctx context.Context, current string, builtin bool) (*Release, error) {
	response, err := c.request(ctx, latestURL)
	if err != nil {
		return nil, errors.New("Couldn’t check GitHub for updates. Try again when online.")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub update check failed (HTTP %d). Try again later.", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 2<<20+1))
	if err != nil || len(raw) > 2<<20 {
		return nil, errors.New("Could not read the GitHub release")
	}
	var release struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
		Assets     []struct {
			Name   string
			URL    string `json:"browser_download_url"`
			Digest string
			Size   int64
		}
	}
	if json.Unmarshal(raw, &release) != nil {
		return nil, errors.New("Invalid GitHub release response")
	}
	if release.Draft || release.Prerelease {
		return nil, nil
	}
	version := strings.TrimPrefix(release.Tag, "v")
	if release.Tag != "v"+version {
		return nil, errors.New("Invalid release tag")
	}
	newer, err := Newer(version, current)
	if err != nil || !newer {
		return nil, err
	}
	for _, asset := range release.Assets {
		if asset.Name != assetName(builtin) {
			continue
		}
		r := Release{Version: version, URL: asset.URL, SHA256: strings.TrimPrefix(asset.Digest, "sha256:"), Size: asset.Size, BuiltinVPN: builtin}
		if !strings.HasPrefix(asset.Digest, "sha256:") || !validRelease(r) {
			return nil, errors.New("The update has no valid GitHub SHA-256 digest or download address")
		}
		return &r, nil
	}
	return nil, errors.New("The latest release does not include this iPhone’s IPA Loader variant. Try again later.")
}

// Download returns a private temporary IPA; callers remove its directory.
func (c *Client) Download(ctx context.Context, release Release, progress func(int64, int64)) (path string, err error) {
	if !validRelease(release) {
		return "", errors.New("Invalid IPA Loader update")
	}
	response, err := c.request(ctx, release.URL)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", errors.New("Could not download the update. Check your internet connection.")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Update download failed (HTTP %d)", response.StatusCode)
	}
	dir, err := os.MkdirTemp("", "ipa-loader-update-")
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(dir)
		}
	}()
	path = filepath.Join(dir, "update.ipa")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	writer := &downloadWriter{Writer: io.MultiWriter(file, hash), total: release.Size, progress: progress}
	n, copyErr := io.Copy(writer, io.LimitReader(response.Body, release.Size+1))
	syncErr := file.Sync()
	closeErr := file.Close()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if copyErr != nil {
		return "", copyErr
	}
	if syncErr != nil {
		return "", syncErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if n != release.Size || hex.EncodeToString(hash.Sum(nil)) != release.SHA256 {
		return "", errors.New("The update download failed its size or SHA-256 check. Try again.")
	}
	if err = ValidatePackage(path, release.Version, release.BuiltinVPN); err != nil {
		return "", err
	}
	return path, nil
}

type downloadWriter struct {
	io.Writer
	n, total int64
	progress func(int64, int64)
	last     time.Time
}

func (w *downloadWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	w.n += int64(n)
	if w.progress != nil && (time.Since(w.last) > 250*time.Millisecond || w.n == w.total) {
		w.last = time.Now()
		w.progress(w.n, w.total)
	}
	return n, err
}
