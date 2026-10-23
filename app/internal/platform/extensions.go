package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"howett.net/plist"
	"ipa-loader/app/internal/apple"
)

func inspectExtension(path string, parent appInfo) (appInfo, error) {
	dir := filepath.Dir(path)
	if dir != filepath.Join(parent.Path, "PlugIns") && dir != filepath.Join(parent.Path, "Extensions") {
		return appInfo{}, failure("App extensions must be in the main app's PlugIns or Extensions directory")
	}
	b, err := readLimited(filepath.Join(path, "Info.plist"), 1<<20)
	if err != nil {
		return appInfo{}, failure("App extension Info.plist is missing")
	}
	m, err := dictionary(b)
	if err != nil {
		return appInfo{}, failure("App extension Info.plist is invalid")
	}
	a := appInfo{Path: path, Executable: stringField(m, "CFBundleExecutable"), BundleID: stringField(m, "CFBundleIdentifier"), Version: stringField(m, "CFBundleShortVersionString"), Build: stringField(m, "CFBundleVersion")}
	if !validText(a.Executable) || a.Executable == "." || a.Executable == ".." || filepath.Base(a.Executable) != a.Executable || strings.ContainsAny(a.Executable, "/\\:") || !bundlePattern.MatchString(a.BundleID) || len(a.BundleID) > 255 || !strings.HasPrefix(a.BundleID, parent.BundleID+".") || stringField(m, "CFBundlePackageType") != "XPC!" {
		return a, failure("Unsupported app extension metadata or parent bundle identifier")
	}
	if !validText(a.Version) || !validText(a.Build) {
		return a, failure("App extension version and build are missing or invalid")
	}
	key, point := "NSExtension", "NSExtensionPointIdentifier"
	if dir == filepath.Join(parent.Path, "Extensions") {
		key, point = "EXAppExtensionAttributes", "EXExtensionPointIdentifier"
	}
	extension, ok := m[key].(map[string]any)
	if !ok || !bundlePattern.MatchString(stringField(extension, point)) {
		return a, failure("App extension point is missing or invalid")
	}
	a.ExtensionPoint = stringField(extension, point)
	if err = inspectMachO(filepath.Join(path, a.Executable), 2); err != nil {
		return a, fmt.Errorf("App extension: %w", err)
	}
	a.Networking, err = readNetworkRequest(filepath.Join(path, a.Executable))
	if err != nil {
		return a, err
	}
	a.Sharing, err = readSharingRequest(filepath.Join(path, a.Executable))
	if err != nil {
		return a, err
	}
	a.Capabilities, err = readCapabilities(filepath.Join(path, a.Executable))
	if err != nil {
		return a, err
	}
	return a, nil
}

// Insert the account suffix at the parent boundary so both installed and
// authorized extension IDs remain children of their corresponding parent ID.
func extensionIdentity(original string, parent bundleIdentity) (bundleIdentity, error) {
	if !bundlePattern.MatchString(original) || !strings.HasPrefix(original, parent.Original+".") {
		return bundleIdentity{}, failure("App extension identifier must start with the containing app identifier")
	}
	suffix := strings.TrimPrefix(original, parent.Original)
	ids := bundleIdentity{Original: original, Registration: parent.Registration + suffix, Installed: parent.Installed + suffix}
	if len(ids.Registration) > 255 || len(ids.Installed) > 255 {
		return ids, failure("App extension identifier is too long for this account")
	}
	return ids, nil
}

func validateExtensionProfile(parent, profile map[string]any, identity, team, udid string, ids bundleIdentity, now time.Time) (map[string]any, error) {
	parentLocal, _ := parent["LocalProvision"].(bool)
	local := false
	if v, present := profile["LocalProvision"]; present {
		var ok bool
		local, ok = v.(bool)
		if !ok {
			return nil, failure("App extension profile has an invalid account type")
		}
	}
	parentPrefixes, prefixes := textList(parent["ApplicationIdentifierPrefix"]), textList(profile["ApplicationIdentifierPrefix"])
	if parentLocal != local || len(parentPrefixes) != 1 || len(prefixes) != 1 || parentPrefixes[0] != prefixes[0] {
		return nil, failure("App and extension profiles must use the same account type and App ID prefix")
	}
	entitlements, err := validateInstalledProfile(profile, identity, team, ids.Registration, ids.Installed, udid, now)
	if err != nil {
		return nil, err
	}
	parentDebug, _ := mapField(parent, "Entitlements")["get-task-allow"].(bool)
	if parentDebug != entitlements["get-task-allow"] {
		return nil, failure("App and extension profiles must agree on debugging authorization")
	}
	return entitlements, nil
}

func (e *engine) prepareExtensions(app *appInfo, client requestClient, session *apple.Session, identity, team, udid string, parentIDs bundleIdentity, parentProfile map[string]any, options ...*sharingContext) error {
	var sharing *sharingContext
	if len(options) > 0 {
		sharing = options[0]
	}
	var omitted []string
	for i := range app.Embedded {
		object := &app.Embedded[i]
		if !object.Extension {
			continue
		}
		if local, _ := parentProfile["LocalProvision"].(bool); local && object.ExtensionPoint == "com.apple.app-migration" {
			e.emit("Skipping app migration extension for free account: " + filepath.Base(object.Path))
			omitted = append(omitted, object.Path)
			continue
		}
		e.emit("Provisioning app extension: " + filepath.Base(object.Path))
		ids, err := extensionIdentity(object.Identifier, parentIDs)
		if err != nil {
			return err
		}
		plan, err := sharingFor(object.Sharing, team, ids.Registration, parentProfile, sharing)
		if err != nil {
			return err
		}
		profile, err := e.provisionAppProfile(client, session, team, ids.Registration, plan.AppGroups...)
		if err != nil {
			return err
		}
		profilePath := filepath.Join(object.Path, "embedded.mobileprovision")
		if err = os.WriteFile(profilePath, profile, 0600); err != nil {
			return failure("Could not embed app extension profile")
		}
		decoded, err := e.decodeProfile(profilePath)
		if err != nil {
			return failure("App extension profile CMS integrity did not verify")
		}
		p, err := dictionary(decoded)
		if err != nil {
			return err
		}
		entitlements, err := validateExtensionProfile(parentProfile, p, identity, team, udid, ids, time.Now())
		if err != nil {
			return err
		}
		if err = authorizeNetwork(p, entitlements, object.Networking); err != nil {
			return err
		}
		e.applyCapabilities(object.Path, p, entitlements, object.Capabilities, map[string]string{parentIDs.Original: parentIDs.Installed, ids.Original: ids.Installed})
		if object.ExtensionPoint == "com.apple.app-migration" && entitlements[migrationAccessKey] == nil {
			// A migration extension cannot access the containing app without this
			// entitlement. Leave the main app and its other extensions usable.
			e.emit("Skipping app migration extension without authorized container access: " + filepath.Base(object.Path))
			omitted = append(omitted, object.Path)
			continue
		}
		extension := appInfo{Path: object.Path, BundleID: object.Identifier}
		// Repacked apps may contain extensions with independent versions. Align
		// their metadata with the containing app before creating the new seal.
		if err = extension.applyBundleMetadata(ids, app.Version, app.Build); err != nil {
			return err
		}
		if err = e.applySharing(object.Path, object.Executable, p, entitlements, plan, sharing); err != nil {
			return err
		}
		encoded, err := plist.Marshal(entitlements, plist.XMLFormat)
		if err != nil {
			return failure("Could not encode app extension entitlements")
		}
		object.Entitlements = filepath.Join(e.work, fmt.Sprintf("extension-entitlements-%d.plist", i))
		if err = os.WriteFile(object.Entitlements, encoded, 0600); err != nil {
			return failure("Could not retain app extension entitlements")
		}
		object.Identifier = ids.Installed
	}
	for _, path := range omitted {
		if err := os.RemoveAll(path); err != nil {
			return failure("Could not remove unsupported app migration extension")
		}
	}
	if len(omitted) > 0 {
		objects := app.Embedded[:0]
		for _, object := range app.Embedded {
			keep := true
			for _, path := range omitted {
				if object.Path == path || strings.HasPrefix(object.Path, path+string(filepath.Separator)) {
					keep = false
				}
			}
			if keep {
				objects = append(objects, object)
			}
		}
		app.Embedded = objects
	}
	return nil
}

func directExtensionPaths(root string) ([]string, error) {
	var paths []string
	for _, directory := range []string{"PlugIns", "Extensions"} {
		matches, err := filepath.Glob(filepath.Join(root, directory, "*.appex"))
		if err != nil {
			return nil, err
		}
		paths = append(paths, matches...)
	}
	return paths, nil
}
