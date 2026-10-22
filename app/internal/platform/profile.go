package platform

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"time"
)

func textList(v any) []string {
	switch a := v.(type) {
	case []string:
		return a
	case []any:
		r := []string{}
		for _, x := range a {
			s, ok := x.(string)
			if !ok {
				return nil
			}
			r = append(r, s)
		}
		return r
	}
	return nil
}
func recordList(m map[string]any, k string) ([]map[string]any, error) {
	switch a := m[k].(type) {
	case []map[string]any:
		return a, nil
	case []any:
		r := []map[string]any{}
		for _, v := range a {
			x, ok := v.(map[string]any)
			if !ok {
				return nil, failure("Developer service returned an invalid record list")
			}
			r = append(r, x)
		}
		return r, nil
	}
	return nil, failure("Developer service returned an invalid record list")
}
func fingerprint(b []byte) string { h := sha1.Sum(b); return strings.ToUpper(hex.EncodeToString(h[:])) }
func validCert(record map[string]any, now time.Time) *x509.Certificate {
	if record["revoked"] == true || strings.EqualFold(stringField(record, "status"), "revoked") {
		return nil
	}
	data, ok := record["certContent"].([]byte)
	if !ok {
		return nil
	}
	c, e := x509.ParseCertificate(data)
	if e != nil || now.Before(c.NotBefore) || c.NotAfter.Sub(now) < 24*time.Hour {
		return nil
	}
	return c
}
func chooseCertificate(records []map[string]any, identities map[string]bool, now time.Time) map[string]any {
	var selected map[string]any
	var expiry time.Time
	var selectedFP string
	for _, r := range records {
		c := validCert(r, now)
		if c == nil {
			continue
		}
		fp := fingerprint(c.Raw)
		if identities[fp] && (c.NotAfter.After(expiry) || (c.NotAfter.Equal(expiry) && fp > selectedFP)) {
			selected = r
			expiry = c.NotAfter
			selectedFP = fp
		}
	}
	return selected
}
func validateProfile(p map[string]any, identity, team, bundle, udid string, now time.Time) (map[string]any, error) {
	if !contains(textList(p["Platform"]), "iOS") {
		return nil, failure("Profile is not for iPhone")
	}
	expiry, ok := p["ExpirationDate"].(time.Time)
	if !ok || !expiry.After(now) {
		return nil, failure("Provisioning profile has expired or has no expiry")
	}
	if created, ok := p["CreationDate"].(time.Time); ok && created.After(now) {
		return nil, failure("Provisioning profile is not yet valid")
	}
	teams := textList(p["TeamIdentifier"])
	prefixes := textList(p["ApplicationIdentifierPrefix"])
	if len(teams) != 1 || teams[0] != team || len(prefixes) != 1 {
		return nil, failure("Provisioning profile belongs to a different team")
	}
	found := false
	switch certs := p["DeveloperCertificates"].(type) {
	case []any:
		for _, v := range certs {
			if b, ok := v.([]byte); ok && fingerprint(b) == identity {
				found = true
			}
		}
	case [][]byte:
		for _, b := range certs {
			if fingerprint(b) == identity {
				found = true
			}
		}
	}
	if !found {
		return nil, failure("Provisioning profile does not include the signing identity")
	}
	if !contains(textList(p["ProvisionedDevices"]), udid) {
		return nil, failure("Provisioning profile does not include this iPhone")
	}
	ent, ok := p["Entitlements"].(map[string]any)
	if !ok {
		return nil, failure("Provisioning profile entitlements are missing")
	}
	desired := prefixes[0] + "." + bundle
	authorized := stringField(ent, "application-identifier")
	if !authorizedID(authorized, desired) || stringField(ent, "com.apple.developer.team-identifier") != team {
		return nil, failure("Provisioning profile does not authorize this app")
	}
	groupOK := false
	for _, g := range textList(ent["keychain-access-groups"]) {
		if authorizedID(g, desired) {
			groupOK = true
		}
	}
	if !groupOK {
		return nil, failure("Provisioning profile does not authorize the app keychain group")
	}
	debug := false
	if value, ok := ent["get-task-allow"]; ok {
		var valid bool
		debug, valid = value.(bool)
		if !valid {
			return nil, failure("Invalid profile debugging entitlement")
		}
	}
	return map[string]any{"application-identifier": desired, "com.apple.developer.team-identifier": team, "get-task-allow": debug, "keychain-access-groups": []string{desired}}, nil
}

func validateResolvedProfile(p map[string]any, identity, team string, ids bundleIdentity, udid string, now time.Time) (map[string]any, error) {
	if !ids.valid(team) {
		return nil, failure("Invalid relationship between installed and registered app identifiers")
	}
	return validateInstalledProfile(p, identity, team, ids.Registration, ids.Installed, udid, now)
}

func validateInstalledProfile(p map[string]any, identity, team, registration, installed, udid string, now time.Time) (map[string]any, error) {
	entitlements, err := validateProfile(p, identity, team, registration, udid, now)
	if err != nil {
		return nil, err
	}
	local := false
	if value, present := p["LocalProvision"]; present {
		var ok bool
		local, ok = value.(bool)
		if !ok {
			return nil, failure("Provisioning profile has an invalid account type")
		}
	}
	if local && installed != registration {
		return nil, failure("A free-account profile requires the team-suffixed installed identifier")
	}
	if !local {
		// The retained paid-account reference preserves the profile's keychain
		// groups verbatim, including its authorized wildcard and shared group.
		profileEntitlements := p["Entitlements"].(map[string]any)
		groups := textList(profileEntitlements["keychain-access-groups"])
		for _, group := range groups {
			if !validText(group) {
				return nil, failure("Profile has an invalid keychain group")
			}
		}
		entitlements["keychain-access-groups"] = append([]string(nil), groups...)
	}
	return entitlements, nil
}
func contains(a []string, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}
func authorizedID(pattern, value string) bool {
	return pattern == value || (strings.HasSuffix(pattern, ".*") && strings.HasPrefix(value, strings.TrimSuffix(pattern, "*")))
}
