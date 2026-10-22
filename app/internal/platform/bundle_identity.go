package platform

// bundleIdentity separates the portal/profile identity from CFBundleIdentifier.
// Sideloadly's standard path registers original + "." + team; its paid-profile
// path can restore the original metadata ID while retaining that authorization.
type bundleIdentity struct {
	Original, Registration, Installed string
}

func standardBundleIdentity(original, team string) (bundleIdentity, error) {
	if !bundlePattern.MatchString(original) || !validText(team) {
		return bundleIdentity{}, failure("Invalid app or developer team identifier")
	}
	for _, c := range team {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return bundleIdentity{}, failure("Invalid developer team identifier")
		}
	}
	registration := original + "." + team
	if len(registration) > 255 {
		return bundleIdentity{}, failure("The app identifier is too long to append the developer team ID")
	}
	return bundleIdentity{Original: original, Registration: registration, Installed: registration}, nil
}

func installedTeam(app map[string]any) string {
	team := stringField(app, "teamIdentifier")
	if team == "" {
		team = stringField(mapField(app, "signingInfo"), "teamIdentifier")
	}
	return team
}

// LocalProvision is read from the actual downloaded profile, independently of
// the UI's membership/quota classification. Missing is false, as in the target's
// profile.get("LocalProvision") branch. Malformed wire types are rejected.
func (ids bundleIdentity) withProfile(profile map[string]any, team string, installed []map[string]any) (bundleIdentity, error) {
	local := false
	if value, present := profile["LocalProvision"]; present {
		var ok bool
		local, ok = value.(bool)
		if !ok {
			return ids, failure("Provisioning profile has an invalid account type")
		}
	}
	originalPresent, registeredPresent := false, false
	for _, app := range installed {
		id := stringField(app, "bundleIdentifier")
		if id == ids.Original {
			originalPresent = true
		}
		if id == ids.Registration {
			registeredPresent = true
		}
	}
	if !local {
		// Preserve an already installed suffixed identity rather than changing
		// it on paid-account updates. Ambiguous copies need an explicit choice.
		if originalPresent && registeredPresent {
			return ids, failure("Both original and team-suffixed copies are installed; automatic update selection is ambiguous")
		}
		if !registeredPresent {
			ids.Installed = ids.Original
		}
	}
	for _, app := range installed {
		if stringField(app, "bundleIdentifier") == ids.Installed {
			owner := installedTeam(app)
			if owner != "" && owner != team {
				return ids, failure("The existing app belongs to a different signing team. Use its original account to update it without removing its data")
			}
		}
	}
	return ids, nil
}

func (ids bundleIdentity) valid(team string) bool {
	expected, err := standardBundleIdentity(ids.Original, team)
	return err == nil && ids.Registration == expected.Registration &&
		(ids.Installed == ids.Original || ids.Installed == ids.Registration)
}
