package platform

import (
	"fmt"
	"path/filepath"
	"sort"
)

const migrationAccessKey = "com.apple.developer.app-migration.data-container-access"

// These capabilities can be omitted when re-signing under a different team.
// Identity, sharing and Network Extensions have separate, mandatory policies.
// Unknown entitlements remain unsupported instead of being silently discarded.
var optionalCapabilityTypes = map[string]string{
	"aps-environment":                        "environment",
	"com.apple.developer.associated-domains": "strings",
	"com.apple.developer.coremedia.allow-alternate-video-decoder-selection": "bool",
	"com.apple.developer.declared-age-range":                                "bool",
	"com.apple.developer.device-information.user-assigned-device-name":      "bool",
	"com.apple.developer.group-session":                                     "bool",
	"com.apple.developer.networking.multicast":                              "bool",
	"com.apple.developer.networking.wifi-info":                              "bool",
	"com.apple.developer.siri":                                              "bool",
	"com.apple.developer.storekit.request-data":                             "bool",
	"com.apple.developer.usernotifications.communication":                   "bool",
	"com.apple.developer.usernotifications.time-sensitive":                  "bool",
	migrationAccessKey: "bundles",
}

type capabilityRequest map[string]any

func requestedCapabilities(ent map[string]any) (capabilityRequest, error) {
	r := capabilityRequest{}
	for key, kind := range optionalCapabilityTypes {
		value, present := ent[key]
		if !present {
			continue
		}
		valid := false
		switch kind {
		case "bool":
			_, valid = value.(bool)
		case "environment":
			valid = value == "development" || value == "production"
		case "strings", "bundles":
			values, err := sharingStrings(value)
			valid = err == nil && len(values) > 0
			for _, v := range values {
				if kind == "bundles" && !bundlePattern.MatchString(v) {
					valid = false
				}
			}
			value = values
		}
		if !valid {
			return nil, fmt.Errorf("Malformed capability entitlement: %s", key)
		}
		r[key] = value
	}
	return r, nil
}

func readCapabilities(path string) (capabilityRequest, error) {
	b, err := readLimited(path, 512<<20)
	if err != nil {
		return nil, err
	}
	slices, err := machSlices(b)
	if err != nil {
		return nil, err
	}
	ent, err := consistentSliceEntitlements(slices)
	if err != nil {
		return nil, err
	}
	return requestedCapabilities(ent)
}

// Only a verified new profile grants capabilities. Source signatures express
// requests; they cannot grant the original developer's permissions to a new team.
func (e *engine) applyCapabilities(bundle string, profile, signing map[string]any, request capabilityRequest, identities map[string]string) []string {
	allowed := mapField(profile, "Entitlements")
	var omitted []string
	keys := make([]string, 0, len(request))
	for key := range request {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := request[key]
		mapped := true
		if key == migrationAccessKey {
			var bundles []string
			for _, original := range textList(value) {
				installed, ok := identities[original]
				if !ok {
					mapped = false
					break
				}
				bundles = append(bundles, installed)
			}
			value = bundles
		}
		// Development signing uses the environment issued in the new profile.
		if key == "aps-environment" {
			environment := stringField(allowed, key)
			if environment == "development" || environment == "production" {
				value = environment
			}
		}
		if mapped && profileAuthorizes(allowed[key], value) {
			signing[key] = value
		} else {
			omitted = append(omitted, key)
			e.emit(fmt.Sprintf("%s: omitting capability not authorized by the new profile: %s", filepath.Base(bundle), key))
		}
	}
	return omitted
}
