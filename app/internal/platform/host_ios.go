//go:build ios

package platform

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"ipa-loader/app/internal/apple"
	"ipa-loader/app/internal/iosnative"
	"ipa-loader/app/internal/mobiledevice"
	"ipa-loader/app/internal/securestore"
	"ipa-loader/app/internal/signing"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const sharingRuntimeDir = "sharing-ios"
const sharingRecipe = "build-sharing-macos.go"

var hostDevices = mobiledevice.WindowsDevices
var hostLocked = mobiledevice.WindowsLocked
var hostInstalledApps = mobiledevice.WindowsInstalledApps

func Devices(ctx context.Context) ([]Device, error) {
	if err := iosnative.ConnectVPN(); err != nil {
		return nil, err
	}
	records, err := hostDevices(ctx)
	if err != nil {
		return nil, err
	}
	devices := make([]Device, 0, len(records))
	for _, r := range records {
		devices = append(devices, Device{ID: r.UDID, UDID: r.UDID, Name: r.Name, Model: r.Model, OSVersion: r.OSVersion, Transport: "WiFi"})
	}
	return devices, nil
}
func Sideload(ctx context.Context, c *apple.Client, s *apple.Session, team, ipa string, d Device, p func(Progress)) (Result, error) {
	if err := iosnative.ConnectVPN(); err != nil {
		return Result{}, err
	}
	result, err := sideload(ctx, c, s, team, ipa, d, p, newIOSEngine(team, s.Username))
	if err == nil && result.Installed {
		if result.BundleID != iosnative.BundleID() {
			if IOSPackageRetention(ctx) {
				if retainErr := retainIOSPackage(result.BundleID, ipa); retainErr != nil {
					result.CompletionMessage = "App installed. Its fallback IPA could not be saved. Profile refresh is still available; full signing may ask for the original IPA."
				}
			} else if removeErr := discardIOSPackage(result.BundleID, ipa); removeErr != nil {
				result.CompletionMessage = "App installed, but its previous saved IPA could not be removed."
			}
		}
		// A confirmed install has already persisted its signing proof and history.
		// Do not leave another potentially multi-GB extracted copy in tmp.
		if result.WorkDir != "" && filepath.Dir(filepath.Clean(result.WorkDir)) == filepath.Clean(os.TempDir()) && strings.HasPrefix(filepath.Base(result.WorkDir), "ipa-loader-install-") {
			if cleanErr := os.RemoveAll(result.WorkDir); cleanErr != nil {
				result.CompletionMessage = "App installed, but temporary installation files could not be removed."
			} else {
				result.WorkDir = ""
			}
		}
	}
	return result, err
}
func newIOSEngine(team, account string) func(context.Context, string) *engine {
	return func(ctx context.Context, work string) *engine {
		root, rootErr := os.UserConfigDir()
		e := newEngine(ctx, work)
		e.host = &iosHost{desktopHost: &desktopHost{team: team, vault: signing.IdentityVault{Dir: filepath.Join(root, "ipa-loader", "signing")}}, account: account}
		e.configDir = func() (string, error) { return root, rootErr }
		return e
	}
}

type iosHost struct {
	*desktopHost
	account string
}

func (h *iosHost) checkTools(e *engine) error { _, err := e.configDir(); return err }
func (h *iosHost) sharingLibrary(e *engine) (string, error) {
	root := filepath.Join(e.work, sharingRuntimeDir)
	if err := privateDir(root); err != nil {
		return "", err
	}
	z, err := zip.OpenReader(filepath.Join(filepath.Dir(IOSExecutable()), sharingRuntimeDir+".zip"))
	if err != nil {
		return "", err
	}
	defer z.Close()
	var total uint64
	for _, member := range z.File {
		if member.FileInfo().IsDir() {
			continue
		}
		name := filepath.FromSlash(member.Name)
		if !filepath.IsLocal(name) || strings.Contains(member.Name, "\\") || member.Mode()&os.ModeSymlink != 0 || member.UncompressedSize64 > 8<<20 {
			return "", failure("Invalid sharing runtime archive")
		}
		total += member.UncompressedSize64
		if total > 16<<20 {
			return "", failure("Sharing runtime archive exceeds its bound")
		}
		target := filepath.Join(root, name)
		if err = privateDir(filepath.Dir(target)); err != nil {
			return "", err
		}
		input, err := member.Open()
		if err != nil {
			return "", err
		}
		body, err := io.ReadAll(io.LimitReader(input, 8<<20+1))
		input.Close()
		if err != nil || len(body) > 8<<20 {
			return "", failure("Invalid sharing runtime member")
		}
		if err = exclusive(target, body); err != nil {
			return "", err
		}
	}
	return e.copyWindowsSharingLibrary(root)
}
func IOSExecutable() string { p, _ := os.Executable(); return p }

func (h *iosHost) install(e *engine, app appInfo, d Device, result *Result, notify func(float64, string)) error {
	if updating, _ := e.ctx.Value(selfUpdateKey{}).(bool); updating && app.BundleID != iosnative.BundleID() {
		return failure("The update would change IPA Loader’s installed identity. Use the original developer team.")
	}
	end := iosnative.BeginTask()
	defer end()
	if app.BundleID == iosnative.BundleID() {
		profile, err := os.ReadFile(filepath.Join(app.Path, "embedded.mobileprovision"))
		if err != nil {
			return err
		}
		currentProfile, _ := os.ReadFile(filepath.Join(filepath.Dir(IOSExecutable()), "embedded.mobileprovision"))
		requestedAt := time.Now().UTC()
		if sha256.Sum256(currentProfile) == sha256.Sum256(profile) {
			requestedAt = time.Time{}
		}
		receipt := refreshReceipt{BundleID: app.BundleID, Version: app.Version, Build: app.Build, ProfileHash: sha256.Sum256(profile), RequestedAt: requestedAt, Account: h.account}
		raw, err := json.Marshal(receipt)
		if err != nil {
			return err
		}
		root, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		if err = securestore.Write(filepath.Join(root, "ipa-loader", "refresh-receipt.secret"), raw); err != nil {
			return err
		}
		message := "Refreshing IPA Loader. Return to the Home Screen when installation starts, then reopen it"
		if updating, _ := e.ctx.Value(selfUpdateKey{}).(bool); updating {
			message = "Updating IPA Loader. Return to the Home Screen when installation starts, then reopen it"
		}
		notify(.64, message)
	}
	var binding *refreshBinding
	if identity, loadErr := h.vault.Load(h.team); loadErr == nil {
		binding, _ = captureRefreshBinding(e.ctx, app.Path, identity.Certificate.Raw)
	}
	if err := e.ctx.Err(); err != nil {
		return err
	}
	err := h.desktopHost.install(e, app, d, result, notify)
	if err == nil && result.Installed {
		if historyErr := recordIOSInstall(app, h.account, binding); historyErr != nil {
			result.CompletionMessage = "App installed. Its refresh history could not be saved; pull down in Apps to check its expiry."
		}
	}
	return err
}

type refreshReceipt struct {
	BundleID, Version, Build string
	ProfileHash              [32]byte
	RequestedAt              time.Time
	Account                  string
}

// confirmedIOSRefresh confirms replacement using the installed profile, independently
// of the process that submitted the update. A submission alone is not success.
func confirmedIOSRefresh() (refreshReceipt, bool) {
	root, err := os.UserConfigDir()
	if err != nil {
		return refreshReceipt{}, false
	}
	raw, err := securestore.Read(filepath.Join(root, "ipa-loader", "refresh-receipt.secret"), 4096)
	if err != nil || len(raw) == 0 {
		return refreshReceipt{}, false
	}
	var receipt refreshReceipt
	if json.Unmarshal(raw, &receipt) != nil || receipt.BundleID != iosnative.BundleID() {
		return refreshReceipt{}, false
	}
	bundle := filepath.Dir(IOSExecutable())
	profile, err := os.ReadFile(filepath.Join(bundle, "embedded.mobileprovision"))
	if err != nil {
		return refreshReceipt{}, false
	}
	info, err := os.ReadFile(filepath.Join(bundle, "Info.plist"))
	if err != nil {
		return refreshReceipt{}, false
	}
	meta, err := dictionary(info)
	if err != nil {
		return refreshReceipt{}, false
	}
	if sha256.Sum256(profile) == receipt.ProfileHash && stringField(meta, "CFBundleShortVersionString") == receipt.Version && stringField(meta, "CFBundleVersion") == receipt.Build {
		return receipt, true
	}
	return refreshReceipt{}, false
}
