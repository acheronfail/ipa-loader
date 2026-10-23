package platform

import (
	"encoding/binary"
	"path/filepath"
	"sort"
	"strings"
)

func readSharingRequest(path string) (sharingRequest, error) {
	b, err := readLimited(path, 512<<20)
	if err != nil {
		return sharingRequest{}, err
	}
	slices, err := machSlices(b)
	if err != nil {
		return sharingRequest{}, err
	}
	ent, err := consistentSliceEntitlements(slices)
	if err != nil {
		return sharingRequest{}, err
	}
	request, err := requestedSharing(ent)
	if err != nil {
		return request, err
	}
	// Local fallback groups are deliberately absent from signed entitlements.
	// Recover their requests from validated managed metadata when re-signing.
	dir := filepath.Dir(path)
	if ext := filepath.Ext(dir); ext == ".app" || ext == ".appex" {
		if raw, readErr := readLimited(filepath.Join(dir, "Info.plist"), 1<<20); readErr == nil {
			info, err := dictionary(raw)
			if err != nil {
				return request, err
			}
			managed, err := sharingMetadata(info)
			if err != nil {
				return request, err
			}
			if managed {
				local, _ := mapField(info, "IPALoaderSharing")["LocalAppGroups"].(map[string]any)
				for source := range local {
					if !contains(request.AppGroups, source) {
						request.AppGroups = append(request.AppGroups, source)
					}
				}
				sort.Strings(request.AppGroups)
			}
		}
	}
	return request, nil
}

func thinEntitlements(b []byte) (map[string]any, error) {
	if len(b) < 32 || binary.LittleEndian.Uint32(b) != 0xfeedfacf {
		return nil, failure("Unsupported executable while reading sharing entitlements")
	}
	count, size := binary.LittleEndian.Uint32(b[16:]), uint64(binary.LittleEndian.Uint32(b[20:]))
	if count > 100000 || size > uint64(len(b)-32) {
		return nil, failure("Invalid executable while reading sharing entitlements")
	}
	offset, end := 32, 32+int(size)
	for i := uint32(0); i < count; i++ {
		if offset+8 > end {
			return nil, failure("Truncated executable while reading sharing entitlements")
		}
		cmd, n := binary.LittleEndian.Uint32(b[offset:]), int(binary.LittleEndian.Uint32(b[offset+4:]))
		if n < 8 || n > end-offset {
			return nil, failure("Invalid executable command while reading sharing entitlements")
		}
		if cmd == 0x1d {
			if n < 16 {
				return nil, failure("Invalid executable signature command")
			}
			start, length := uint64(binary.LittleEndian.Uint32(b[offset+8:])), uint64(binary.LittleEndian.Uint32(b[offset+12:]))
			if start > uint64(len(b)) || length > uint64(len(b))-start {
				return nil, failure("Invalid executable signature range")
			}
			ent, err := signatureEntitlements(b[start : start+length])
			if err != nil {
				return nil, err
			}
			return ent, nil
		}
		offset += n
	}
	return nil, nil
}

// sharingRequest is the original app's requested sharing relationships. It
// never confers authorization; every mapped value must be checked against the
// new profile before it is used as a signing entitlement.
type sharingRequest struct {
	ApplicationID             string
	AppGroups, KeychainGroups []string
}

type sharingPlan struct {
	AppGroups, KeychainGroups        []string
	AppGroupAliases, KeychainAliases map[string]string
	LocalAppGroups                   map[string]string
}

func sharingStrings(value any) ([]string, error) {
	var values []string
	switch v := value.(type) {
	case []any:
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, failure("Invalid sharing entitlement array")
			}
			values = append(values, s)
		}
	case []string:
		values = append(values, v...)
	default:
		return nil, failure("Invalid sharing entitlement array")
	}
	if len(values) > 64 {
		return nil, failure("Too many sharing groups")
	}
	seen := map[string]bool{}
	for _, value := range values {
		if len(value) > 255 || !validText(value) || seen[value] {
			return nil, failure("Invalid or duplicate sharing group")
		}
		seen[value] = true
	}
	return values, nil
}

func requestedSharing(entitlements map[string]any) (sharingRequest, error) {
	r := sharingRequest{ApplicationID: stringField(entitlements, "application-identifier")}
	if value, present := entitlements["com.apple.security.application-groups"]; present {
		groups, err := sharingStrings(value)
		if err != nil {
			return r, err
		}
		for _, group := range groups {
			if !strings.HasPrefix(group, "group.") || !bundlePattern.MatchString(group) {
				return r, failure("Invalid app group identifier")
			}
		}
		r.AppGroups = groups
	}
	if value, present := entitlements["keychain-access-groups"]; present {
		groups, err := sharingStrings(value)
		if err != nil {
			return r, err
		}
		prefix, _, ok := strings.Cut(r.ApplicationID, ".")
		if len(groups) > 0 && (!ok || prefix == "" || !bundlePattern.MatchString(r.ApplicationID)) {
			return r, failure("Keychain sharing requires a valid original application identifier")
		}
		for _, group := range groups {
			if group == "com.apple.token" || group == prefix+".*" {
				continue
			}
			if !strings.HasPrefix(group, prefix+".") || !bundlePattern.MatchString(group) {
				return r, failure("Keychain group must use the original App ID prefix")
			}
		}
		r.KeychainGroups = groups
	}
	return r, nil
}

// planSharing separates source aliases (used by app code) from newly authorized
// IDs. Runtime mapping preserves the original literals used by app code;
// downloaded profiles must authorize every mapped signing entitlement.
func planSharing(request sharingRequest, team, prefix, registration string, bundleRegistrations map[string]string) (sharingPlan, error) {
	p := sharingPlan{AppGroupAliases: map[string]string{}, KeychainAliases: map[string]string{}}
	if !bundlePattern.MatchString(registration) || !validAccountComponent(team) || !validAccountComponent(prefix) {
		return p, failure("Invalid sharing identity")
	}
	for _, group := range request.AppGroups {
		mapped := group + "." + team
		if strings.HasSuffix(group, "."+team) {
			mapped = group
		}
		if len(mapped) > 255 {
			return p, failure("App group identifier is too long for this account")
		}
		p.AppGroupAliases[group] = mapped
		p.AppGroups = append(p.AppGroups, mapped)
	}
	originalPrefix, _, _ := strings.Cut(request.ApplicationID, ".")
	for _, group := range request.KeychainGroups {
		switch group {
		case "com.apple.token":
			continue // never request or invent an Apple-only namespace
		case originalPrefix + ".*":
			continue // default access is materialized to the new application ID
		}
		mapped := prefix + "." + strings.TrimPrefix(group, originalPrefix+".")
		if registered, ok := bundleRegistrations[strings.TrimPrefix(group, originalPrefix+".")]; ok {
			mapped = prefix + "." + registered
		}
		if group == request.ApplicationID {
			mapped = prefix + "." + registration
		}
		if len(mapped) > 255 {
			return p, failure("Keychain group identifier is too long for this account")
		}
		p.KeychainAliases[group] = mapped
		p.KeychainGroups = append(p.KeychainGroups, mapped)
	}
	// Keep the app's own concrete group first for unqualified SecItem requests.
	self := prefix + "." + registration
	groups := []string{self}
	seen := map[string]bool{self: true}
	for _, group := range p.KeychainGroups {
		if !seen[group] {
			groups = append(groups, group)
			seen[group] = true
		}
	}
	p.KeychainGroups = groups
	sort.Strings(p.AppGroups)
	return p, nil
}

func validAccountComponent(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func authorizeSharing(profile map[string]any, plan sharingPlan) error {
	entitlements, ok := profile["Entitlements"].(map[string]any)
	if !ok {
		return failure("Profile entitlements are missing")
	}
	allowedGroups := textList(entitlements["com.apple.security.application-groups"])
	for _, group := range plan.AppGroups {
		if !contains(allowedGroups, group) {
			return failure("Profile does not authorize a required app group")
		}
	}
	allowedKeychain := textList(entitlements["keychain-access-groups"])
	for _, group := range plan.KeychainGroups {
		authorized := false
		for _, pattern := range allowedKeychain {
			if authorizedID(pattern, group) {
				authorized = true
				break
			}
		}
		if !authorized {
			return failure("Profile does not authorize a required keychain group")
		}
	}
	return nil
}
