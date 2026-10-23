package platform

import (
	"context"
	"howett.net/plist"
	"ipa-loader/app/internal/apple"
	"os"
	"path/filepath"
	"time"
)

func sideload(ctx context.Context, client *apple.Client, session *apple.Session, teamID, ipaPath string, device Device, progress func(Progress), factory func(context.Context, string) *engine) (result Result, err error) {
	if client == nil || session == nil || !validText(teamID) || !validText(device.ID) {
		return result, failure("Select an account, team and iPhone before installing")
	}
	work, err := privateTempDir("", "ipa-loader-install-")
	if err != nil {
		return result, failure("Could not create private installation workspace")
	}
	result.WorkDir = work
	e := factory(ctx, work)
	notify := func(f float64, message string) {
		if progress != nil {
			progress(Progress{f, message})
		}
	}
	defer func() {
		if err != nil && ctx.Err() != nil {
			action := "Installation cancelled"
			if ctx.Err() == context.DeadlineExceeded {
				action = "Installation timed out"
			}
			if result.InstallSubmitted {
				err = failure(action + "; the iPhone may still finish installing. Check it before trying again")
			} else {
				err = failure(action + " before installation was submitted to the iPhone")
			}
		}
	}()
	notify(0, "Checking IPA compatibility")
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	app, err := extractIPA(ctx, ipaPath, work)
	if err != nil {
		return result, err
	}
	result.BundleID, result.Version, result.Build = app.BundleID, app.Version, app.Build
	notify(.15, "Reading target iPhone identity")
	if err = e.checkDeveloperTools(); err != nil {
		return result, err
	}
	details, err := e.deviceJSON("device-details", "device", "info", "details", "--device", device.ID)
	if err != nil {
		return result, err
	}
	hardware, _ := details["hardwareProperties"].(map[string]any)
	udid := stringField(hardware, "udid")
	if !validText(udid) {
		return result, failure("The selected device did not provide an iPhone UDID")
	}
	device.UDID = udid
	if err = e.checkInstallDevice(device); err != nil {
		return result, err
	}
	if err = e.checkDeviceUnlocked(device); err != nil {
		return result, err
	}
	ids, err := standardBundleIdentity(app.BundleID, teamID)
	if err != nil {
		return result, err
	}
	e.networkRequests = map[string]networkRequest{ids.Registration: app.Networking}
	// Bound every derived extension ID before any developer-portal mutation.
	for _, object := range app.Embedded {
		if object.Extension {
			child, childErr := extensionIdentity(object.Identifier, ids)
			if childErr != nil {
				err = childErr

				return result, err
			}
			e.networkRequests[child.Registration] = object.Networking
		}
	}
	sharing, err := e.preflightSharing(app, teamID, ids)
	if err != nil {
		return result, err
	}
	var requestedAppGroups []string
	if sharing != nil {
		preliminary, planErr := planSharing(app.Sharing, teamID, "TESTPREFIX", ids.Registration, sharing.Registrations)
		if planErr != nil {
			return result, planErr
		}
		requestedAppGroups = preliminary.AppGroups
	}
	notify(.2, "Resolving app identity")
	var existingApps []map[string]any
	for _, bundle := range []string{ids.Original, ids.Registration} {
		existing, queryErr := e.deviceJSON("existing-app", "device", "info", "apps", "--device", device.ID, "--bundle-id", bundle)
		if queryErr != nil {
			return result, queryErr
		}
		records, queryErr := recordList(existing, "apps")
		if queryErr != nil {
			return result, queryErr
		}
		for _, record := range records {
			if stringField(record, "bundleIdentifier") == bundle {
				existingApps = append(existingApps, record)
			}
		}
	}
	notify(.25, "Preparing account signing material with the team-suffixed app identifier")
	e.message = func(message string) { notify(.25, message) }
	identity, profile, err := e.provision(client, session, teamID, udid, ids.Registration, requestedAppGroups...)
	if err != nil {
		return result, err
	}
	profilePath := filepath.Join(work, "downloaded.mobileprovision")
	if err = os.WriteFile(profilePath, profile, 0600); err != nil {
		return result, failure("Could not retain downloaded profile")
	}
	decoded, err := e.decodeProfile(profilePath)
	if err != nil {
		return result, failure("Downloaded profile CMS integrity did not verify")
	}
	p, err := dictionary(decoded)
	if err != nil {
		return result, err
	}
	// Validate authorization for the registration ID before allowing profile
	// metadata to influence the installed bundle ID.
	entitlements, err := validateProfile(p, identity, teamID, ids.Registration, udid, time.Now())
	if err != nil {
		return result, err
	}
	ids, err = ids.withProfile(p, teamID, existingApps)
	if err != nil {
		return result, err
	}
	entitlements, err = validateResolvedProfile(p, identity, teamID, ids, udid, time.Now())
	if err != nil {
		return result, err
	}
	if err = authorizeNetwork(p, entitlements, app.Networking); err != nil {
		return result, err
	}
	e.applyCapabilities(app.Path, p, entitlements, app.Capabilities, map[string]string{ids.Original: ids.Installed})
	if ids.Installed == ids.Original {
		notify(.5, "Paid profile: keeping the original installed app identifier")
	} else {
		notify(.5, "Using the team-suffixed installed app identifier")
	}
	if err = app.applyBundleIdentity(ids); err != nil {
		return result, err
	}
	if err = e.prepareExtensions(&app, client, session, identity, teamID, udid, ids, p, sharing); err != nil {
		return result, err
	}
	plan, err := sharingFor(app.Sharing, teamID, ids.Registration, p, sharing)
	if err != nil {
		return result, err
	}
	if err = e.applySharing(app.Path, filepath.Join(app.Path, app.Executable), p, entitlements, plan, sharing); err != nil {
		return result, err
	}
	if sharing != nil {
		if err = refreshSigningGraph(e, &app); err != nil {
			return result, err
		}
	}
	result.BundleID = ids.Installed
	encoded, err := plist.Marshal(entitlements, plist.XMLFormat)
	if err != nil {
		return result, failure("Could not encode signing entitlements")
	}
	entPath := filepath.Join(work, "entitlements.plist")
	if err = os.WriteFile(entPath, encoded, 0600); err != nil {
		return result, failure("Could not write signing entitlements")
	}
	if err = os.WriteFile(filepath.Join(app.Path, "embedded.mobileprovision"), profile, 0600); err != nil {
		return result, failure("Could not embed provisioning profile")
	}
	if err = os.Chmod(filepath.Join(app.Path, app.Executable), 0755); err != nil {
		return result, failure("Could not set executable permissions")
	}
	notify(.6, "Signing and verifying app")
	e.message = func(message string) { notify(.6, message) }
	if err = e.signApp(app, identity, entPath); err != nil {
		return result, err
	}
	err = e.installNative(app, device, &result, notify)
	return result, err
}
