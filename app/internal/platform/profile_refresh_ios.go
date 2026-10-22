//go:build ios

package platform

import (
	"context"
	"errors"
	"path/filepath"

	"ipa-loader/app/internal/apple"
	"ipa-loader/app/internal/iosnative"
	"ipa-loader/app/internal/mobiledevice"
)

// RefreshIOSApp tries profile renewal first. Full signing is a fallback only for
// an incompatible installation or an explicit device rejection, not for lost
// connections, cancellation, account failures, or unconfirmed profile writes.
func RefreshIOSApp(ctx context.Context, client *apple.Client, session *apple.Session, team, bundleID string, device Device, progress func(Progress)) (Result, error) {
	if session == nil || !bundlePattern.MatchString(bundleID) {
		return Result{}, failure("Sign in and select an installed app to refresh")
	}
	if err := iosnative.ConnectVPN(); err != nil {
		return Result{}, err
	}
	return profileFirstRefresh(ctx, func() (Result, error) {
		return refreshIOSProfiles(ctx, client, session, team, bundleID, device, progress)
	}, func() (Result, error) {
		if bundleID == iosnative.BundleID() {
			return BootstrapLoader(ctx, client, session, team, device, progress)
		}
		packagePath := IOSRefreshPackage(bundleID)
		if packagePath == "" {
			return Result{}, ErrRefreshNeedsIPA
		}
		if progress != nil {
			progress(Progress{Fraction: .05, Message: "This app needs full signing. Using its saved IPA"})
		}
		// Reusing a saved fallback preserves the user’s original retention choice.
		return Sideload(WithIOSPackageRetention(ctx, true), client, session, team, packagePath, device, progress)
	})
}

func refreshIOSProfiles(ctx context.Context, client requestClient, session *apple.Session, team, bundleID string, device Device, progress func(Progress)) (Result, error) {
	iosSetup.RLock()
	config := iosSetup.config
	configuredUDID := ""
	if config != nil {
		configuredUDID = config.UDID
	}
	iosSetup.RUnlock()
	if configuredUDID == "" || device.UDID != configuredUDID {
		return Result{}, failure("Connect the iPhone used for IPA Loader setup")
	}
	e := newEngine(ctx, "")
	_, unlock, err := e.openStagingRegistry(device)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	end := iosnative.BeginTask()
	defer end()
	locked, err := hostLocked(ctx, device.UDID)
	if err != nil {
		return Result{}, err
	}
	if locked {
		return Result{}, failure("Unlock your iPhone before refreshing apps")
	}
	appsMu.Lock()
	record := readAppRecords()[bundleID]
	appsMu.Unlock()
	binding := record.Binding
	if bundleID == iosnative.BundleID() {
		binding, err = selfRefreshBinding(ctx, filepath.Dir(IOSExecutable()))
		if err != nil {
			if ctx.Err() != nil {
				return Result{}, ctx.Err()
			}
			return Result{}, errProfileRefreshUnsupported
		}
		if !sameRefreshCode(binding, record.Binding) {
			record.ProfileRefresh = nil
		}
	}
	if binding == nil {
		return Result{}, errProfileRefreshUnsupported
	}
	if binding.Team != team {
		return Result{}, failure("Refresh this app using its original developer team")
	}
	io := profileRefreshIO{
		inventory: func(ctx context.Context) ([]map[string]any, error) { return hostInstalledApps(ctx, device.UDID) },
		profiles: func(ctx context.Context) ([][]byte, error) {
			return mobiledevice.WindowsProvisioningProfiles(ctx, device.UDID)
		},
		install: func(ctx context.Context, raw []byte) error {
			return mobiledevice.WindowsInstallProvisioningProfile(ctx, device.UDID, raw)
		},
		decode:   decodeRefreshProfile,
		rejected: func(err error) bool { return errors.Is(err, mobiledevice.ErrProfileInstallRejected) },
	}
	receipt, err := refreshProfiles(ctx, client, session, binding, record.ProfileRefresh, device.UDID, io, progress)
	result := Result{BundleID: bundleID, Version: binding.Version, Build: binding.Build}
	if err != nil {
		return result, err
	}
	if receipt == nil {
		appsMu.Lock()
		current := readAppRecords()[bundleID]
		current.BundleID, current.Version, current.Build, current.Team = bundleID, binding.Version, binding.Build, binding.Team
		current.setRefreshBinding(binding)
		current.CheckedAccount = session.Username
		// Reconciliation exposes this account only while the complete original
		// profile proof still matches. Do not invent a renewal timestamp.
		err = saveAppRecord(current)
		appsMu.Unlock()
		if err != nil {
			return result, failure("The profile is current, but its account could not be saved. Try Refresh again")
		}
		result.CompletionMessage = "This app’s signing profile is already current. Its expiry is unchanged."
		return result, nil
	}
	// Only confirmed profile-store readback and unchanged app inventory reach here.
	appsMu.Lock()
	defer appsMu.Unlock()
	current := readAppRecords()[bundleID]
	// Keep the package/icon already associated with this app.
	current.BundleID, current.Version, current.Build, current.Team = bundleID, binding.Version, binding.Build, binding.Team
	if current.Name == "" {
		current.Name = bundleID
	}
	if bundleID == iosnative.BundleID() {
		current.Name = "IPA Loader"
		current.Self = true
	}
	current.Account, current.Expires, current.Refreshed = session.Username, receipt.Expires, receipt.Refreshed
	current.Binding, current.ProfileRefresh = binding, receipt
	result.ProfileRefreshed = true
	if err = saveAppRecord(current); err != nil {
		return result, failure("Profiles were renewed, but refresh history could not be saved. Pull down in Apps to check the expiry")
	}
	result.CompletionMessage = "App refreshed. No reinstallation needed."
	return result, nil
}
