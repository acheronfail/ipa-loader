package platform

import (
	"howett.net/plist"
	"os"
	"path/filepath"
)

type sharingContext struct {
	Adapter       string
	Registrations map[string]string
}

func requiresSharing(request sharingRequest) bool {
	if len(request.AppGroups) > 0 {
		return true
	}
	prefix := request.ApplicationID
	for i, c := range prefix {
		if c == '.' {
			prefix = prefix[:i]
			break
		}
	}
	for _, g := range request.KeychainGroups {
		if g != request.ApplicationID && g != prefix+".*" && g != "com.apple.token" {
			return true
		}
	}
	return false
}

func (e *engine) preflightSharing(app appInfo, team string, ids bundleIdentity) (*sharingContext, error) {
	needed := requiresSharing(app.Sharing)
	ctx := &sharingContext{Registrations: map[string]string{ids.Original: ids.Registration}}
	for _, object := range app.Embedded {
		if object.Extension {
			child, err := extensionIdentity(object.Identifier, ids)
			if err != nil {
				return nil, err
			}
			ctx.Registrations[child.Original] = child.Registration
			needed = needed || requiresSharing(object.Sharing)
		}
	}
	if !needed {
		return nil, nil
	}
	check := func(path string, request sharingRequest, registration string) error {
		infoData, err := readLimited(filepath.Join(filepath.Dir(path), "Info.plist"), 1<<20)
		if err != nil {
			return err
		}
		info, err := dictionary(infoData)
		if err != nil {
			return err
		}
		managed, err := sharingMetadata(info)
		if err != nil {
			return err
		}
		if _, err = os.Lstat(filepath.Join(filepath.Dir(path), "Frameworks", sharingLibraryName)); err == nil && !managed {
			return failure("App contains a conflicting sharing-adapter library")
		}
		if _, err := planSharing(request, team, "TESTPREFIX", registration, ctx.Registrations); err != nil {
			return err
		}
		b, err := readLimited(path, 512<<20)
		if err != nil {
			return err
		}
		_, err = addSharingLoadCommand(b)
		return err
	}
	if err := check(filepath.Join(app.Path, app.Executable), app.Sharing, ids.Registration); err != nil {
		return nil, err
	}
	for _, object := range app.Embedded {
		if object.Extension {
			if err := check(object.Executable, object.Sharing, ctx.Registrations[object.Identifier]); err != nil {
				return nil, err
			}
		}
	}
	e.emit("Preparing shared-storage compatibility adapter")
	var err error
	ctx.Adapter, err = e.buildSharingLibrary()
	if err != nil {
		return nil, err
	}
	return ctx, nil
}

func sharingFor(request sharingRequest, team, registration string, profile map[string]any, ctx *sharingContext) (sharingPlan, error) {
	if ctx == nil {
		return sharingPlan{}, nil
	}
	prefixes := textList(profile["ApplicationIdentifierPrefix"])
	if len(prefixes) != 1 {
		return sharingPlan{}, failure("Sharing profile has an ambiguous App ID prefix")
	}
	plan, err := planSharing(request, team, prefixes[0], registration, ctx.Registrations)
	if err != nil {
		return plan, err
	}
	if local, _ := profile["LocalProvision"].(bool); local {
		plan.LocalAppGroups = plan.AppGroupAliases
		plan.AppGroupAliases = map[string]string{}
		plan.AppGroups = nil
		// Personal Teams may authorize only the bundle's own keychain group.
		// Keep explicit source queries working inside that authorized namespace.
		self := prefixes[0] + "." + registration
		for source := range plan.KeychainAliases {
			plan.KeychainAliases[source] = self
		}
		plan.KeychainGroups = []string{self}
	}
	return plan, nil
}

func (e *engine) applySharing(path, executable string, profile map[string]any, entitlements map[string]any, plan sharingPlan, ctx *sharingContext) error {
	if ctx == nil {
		return nil
	}
	if err := authorizeSharing(profile, plan); err != nil {
		return err
	}
	entitlements["keychain-access-groups"] = append([]string(nil), plan.KeychainGroups...)
	if len(plan.AppGroups) > 0 {
		entitlements["com.apple.security.application-groups"] = append([]string(nil), plan.AppGroups...)
	}
	infoPath := filepath.Join(path, "Info.plist")
	b, err := readLimited(infoPath, 1<<20)
	if err != nil {
		return err
	}
	info, err := dictionary(b)
	if err != nil {
		return err
	}
	old, hasMetadata := info["IPALoaderSharing"]
	if hasMetadata {
		if _, err = sharingMetadata(info); err != nil {
			return err
		}
		m, ok := old.(map[string]any)
		if !ok {
			return failure("Existing sharing metadata is invalid")
		}
		merge := func(key string, aliases map[string]string, authorized []string) error {
			if value, present := m[key]; present {
				previous, ok := value.(map[string]any)
				if !ok {
					return failure("Existing sharing aliases are invalid")
				}
				for source, value := range previous {
					target, ok := value.(string)
					if !ok || !validText(source) {
						return failure("Existing sharing aliases are invalid")
					}
					mapped, found := aliases[target]
					if !found && contains(authorized, target) {
						mapped = target
						found = true
					}
					if !found || !contains(authorized, mapped) {
						return failure("Existing sharing alias is not authorized by the new profile")
					}
					aliases[source] = mapped
				}
			}
			return nil
		}
		if len(plan.LocalAppGroups) > 0 {
			previous, _ := m["AppGroups"].(map[string]any)
			for source, value := range previous {
				target, _ := value.(string)
				local, ok := plan.LocalAppGroups[target]
				if !ok {
					local, ok = plan.LocalAppGroups[source]
				}
				if !ok {
					return failure("Existing app group alias has no local storage mapping")
				}
				plan.LocalAppGroups[source] = local
			}
		} else if err = merge("AppGroups", plan.AppGroupAliases, plan.AppGroups); err != nil {
			return err
		}
		if err = merge("KeychainGroups", plan.KeychainAliases, plan.KeychainGroups); err != nil {
			return err
		}
	}
	info["IPALoaderSharing"] = map[string]any{"Version": 1, "AppGroups": plan.AppGroupAliases, "KeychainGroups": plan.KeychainAliases}
	if len(plan.LocalAppGroups) > 0 {
		info["IPALoaderSharing"].(map[string]any)["LocalAppGroups"] = plan.LocalAppGroups
		e.emit("Free account: app-group storage and keychain aliases are local to this app; cross-extension sharing is unavailable")
	}
	encoded, err := plist.Marshal(info, plist.XMLFormat)
	if err != nil {
		return failure("Could not encode sharing metadata")
	}
	if err = os.WriteFile(infoPath, encoded, 0600); err != nil {
		return failure("Could not write sharing metadata")
	}
	libraryPath := filepath.Join(path, "Frameworks", sharingLibraryName)
	if _, err = os.Lstat(libraryPath); err == nil && !hasMetadata {
		return failure("App contains a conflicting sharing-adapter library")
	}
	if err = os.MkdirAll(filepath.Dir(libraryPath), 0700); err != nil {
		return err
	}
	library, err := readLimited(ctx.Adapter, 16<<20)
	if err != nil {
		return err
	}
	if err = os.WriteFile(libraryPath, library, 0755); err != nil {
		return failure("Could not copy sharing adapter")
	}
	b, err = readLimited(executable, 512<<20)
	if err != nil {
		return err
	}
	patched, err := addSharingLoadCommand(b)
	if err != nil {
		return err
	}
	if err = os.WriteFile(executable, patched, 0755); err != nil {
		return failure("Could not prepare executable sharing support")
	}
	return nil
}

func sharingMetadata(info map[string]any) (bool, error) {
	value, present := info["IPALoaderSharing"]
	if !present {
		return false, nil
	}
	m, ok := value.(map[string]any)
	if !ok {
		return false, failure("Existing sharing metadata is invalid")
	}
	version := m["Version"]
	if version != uint64(1) && version != int64(1) && version != int(1) {
		return false, failure("Existing sharing metadata uses an unsupported version")
	}
	for _, key := range []string{"AppGroups", "KeychainGroups", "LocalAppGroups"} {
		if key == "LocalAppGroups" && m[key] == nil {
			continue
		}
		aliases, ok := m[key].(map[string]any)
		if !ok || len(aliases) > 256 {
			return false, failure("Existing sharing aliases are invalid")
		}
		for source, value := range aliases {
			target, ok := value.(string)
			if !ok || len(source) > 255 || len(target) > 255 || !bundlePattern.MatchString(source) || !bundlePattern.MatchString(target) {
				return false, failure("Existing sharing aliases are invalid")
			}
		}
	}
	return true, nil
}

func refreshSigningGraph(e *engine, app *appInfo) error {
	entitlements := map[string]string{}
	for _, object := range app.Embedded {
		if object.Extension {
			entitlements[object.Path] = object.Entitlements
		}
	}
	objects, err := inspectCode(e.ctx, *app)
	if err != nil {
		return err
	}
	for i := range objects {
		if objects[i].Extension {
			objects[i].Entitlements = entitlements[objects[i].Path]
		}
	}
	app.Embedded = objects
	return nil
}
