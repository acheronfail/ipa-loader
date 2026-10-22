package platform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"ipa-loader/app/internal/apple"
	"ipa-loader/app/internal/cms"
)

// ErrRefreshNeedsIPA means the installed app needs full signing, rather than
// profile renewal. Authentication, transport and uncertain submissions never
// masquerade as this error.
var ErrRefreshNeedsIPA = errors.New("This app needs its original IPA to refresh")
var errProfileRefreshUnsupported = errors.New("This installation requires full signing")
var errProfileRefreshUnconfirmed = errors.New("Profile refresh was not confirmed. Reconnect your iPhone and tap Refresh again")

// Only a proven incompatibility can trigger a second, full signing operation.
func profileFirstRefresh(ctx context.Context, renew, fallback func() (Result, error)) (Result, error) {
	result, err := renew()
	if !errors.Is(err, errProfileRefreshUnsupported) {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	return fallback()
}

type refreshMember struct {
	BundleID, Registration string
	EmbeddedProfileHash    string
	Entitlements           []byte
	Expires                time.Time
}
type refreshBinding struct {
	BundleID, Version, Build, Team string
	Certificate                    []byte
	Members                        []refreshMember
}
type profileRefreshReceipt struct {
	Expiries  []time.Time
	Hashes    []string
	Expires   time.Time
	Refreshed time.Time
	Account   string
}
type profileRefreshIO struct {
	inventory func(context.Context) ([]map[string]any, error)
	profiles  func(context.Context) ([][]byte, error)
	install   func(context.Context, []byte) error
	// Decode is injectable for offline tests. Production always verifies CMS.
	decode   func([]byte) (map[string]any, error)
	rejected func(error) bool
}

func decodeRefreshProfile(raw []byte) (map[string]any, error) {
	content, _, _, err := cms.Verify(raw, nil, nil)
	if err != nil {
		return nil, err
	}
	p, err := dictionary(content)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	p["_ipa_profile_hash"] = hex.EncodeToString(sum[:])
	return p, nil
}
func refreshReceiptPresent(receipt *profileRefreshReceipt, profiles []map[string]any) bool {
	if receipt == nil || len(receipt.Hashes) == 0 {
		return false
	}
	found := map[string]bool{}
	for _, p := range profiles {
		found[stringField(p, "_ipa_profile_hash")] = true
	}
	for _, hash := range receipt.Hashes {
		if !found[hash] {
			return false
		}
	}
	return true
}

// A managed installation records the exact embedded profiles for all code
// members. Other profiles for the same identifier must not erase that proof.
func installedBindingExpiry(binding *refreshBinding, profiles []map[string]any) time.Time {
	if binding == nil || len(binding.Members) == 0 {
		return time.Time{}
	}
	certificate, err := x509.ParseCertificate(binding.Certificate)
	if err != nil {
		return time.Time{}
	}
	receipt := &profileRefreshReceipt{}
	expiry := certificate.NotAfter
	for _, member := range binding.Members {
		if member.EmbeddedProfileHash == "" || member.Expires.IsZero() {
			return time.Time{}
		}
		receipt.Hashes = append(receipt.Hashes, member.EmbeddedProfileHash)
		if member.Expires.Before(expiry) {
			expiry = member.Expires
		}
	}
	if !refreshReceiptPresent(receipt, profiles) {
		return time.Time{}
	}
	return expiry
}

func matchingRefreshApp(binding *refreshBinding, apps []map[string]any) bool {
	if binding == nil || len(binding.Members) == 0 {
		return false
	}
	count := 0
	for _, app := range apps {
		if stringField(app, "CFBundleIdentifier") != binding.BundleID {
			continue
		}
		count++
		if stringField(app, "CFBundleShortVersionString") != binding.Version || stringField(app, "CFBundleVersion") != binding.Build {
			return false
		}
		ent := mapField(app, "Entitlements")
		team := stringField(ent, "com.apple.developer.team-identifier")
		// A profile-only refresh cannot change the existing signed entitlements.
		signed, err := dictionary(binding.Members[0].Entitlements)
		if err != nil || team != binding.Team || !reflect.DeepEqual(ent, signed) {
			return false
		}
	}
	return count == 1
}

// Profiles authorize values; the signed app's values must remain unchanged.
// String and array authorizations may contain Apple's terminal .* wildcard.
func profileAuthorizes(allowed, signed any) bool {
	switch want := signed.(type) {
	case string:
		value, ok := allowed.(string)
		return ok && authorizedID(value, want)
	case bool:
		if !want && allowed == nil {
			return true
		}
		value, ok := allowed.(bool)
		return ok && (!want || value)
	case []any:
		values, ok := allowed.([]any)
		if !ok {
			if ss, yes := allowed.([]string); yes {
				for _, s := range ss {
					values = append(values, s)
				}
			} else {
				return false
			}
		}
		for _, w := range want {
			found := false
			for _, v := range values {
				if profileAuthorizes(v, w) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	case []string:
		values := make([]any, len(want))
		for i, s := range want {
			values[i] = s
		}
		return profileAuthorizes(allowed, values)
	case map[string]any:
		values, ok := allowed.(map[string]any)
		if !ok {
			return false
		}
		for k, v := range want {
			if !profileAuthorizes(values[k], v) {
				return false
			}
		}
		return true
	default:
		return allowed != nil && reflect.DeepEqual(allowed, signed)
	}
}
func validateRefreshProfile(p map[string]any, binding *refreshBinding, member refreshMember, udid string, now time.Time) error {
	if _, err := validateInstalledProfile(p, fingerprint(binding.Certificate), binding.Team, member.Registration, member.BundleID, udid, now); err != nil {
		return fmt.Errorf("%w: %v", errProfileRefreshUnsupported, err)
	}
	signed, err := dictionary(member.Entitlements)
	if err != nil || !profileAuthorizes(mapField(p, "Entitlements"), signed) {
		return fmt.Errorf("%w: the new profile does not authorize the installed entitlements", errProfileRefreshUnsupported)
	}
	expiry, _ := p["ExpirationDate"].(time.Time)
	if expiry.Before(member.Expires) {
		return fmt.Errorf("%w: the new profile would shorten validity", errProfileRefreshUnsupported)
	}
	return nil
}

// Download only profiles for existing registrations. This path never creates or
// revokes certificates, adds App IDs, changes capabilities, or removes profiles.
func refreshProfiles(ctx context.Context, client requestClient, session *apple.Session, binding *refreshBinding, prior *profileRefreshReceipt, udid string, io profileRefreshIO, progress func(Progress)) (*profileRefreshReceipt, error) {
	notify := func(f float64, s string) {
		if progress != nil {
			progress(Progress{Fraction: f, Message: s})
		}
	}
	if binding == nil || len(binding.Members) == 0 || len(binding.Members) > 32 || binding.Members[0].BundleID != binding.BundleID {
		return nil, errProfileRefreshUnsupported
	}
	certificate, err := x509.ParseCertificate(binding.Certificate)
	now := time.Now()
	if err != nil || now.Before(certificate.NotBefore) || certificate.NotAfter.Sub(now) < 24*time.Hour {
		return nil, errProfileRefreshUnsupported
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	baseline := append([]refreshMember(nil), binding.Members...)
	if prior != nil && len(prior.Expiries) == len(baseline) {
		raw, readErr := io.profiles(ctx)
		if readErr != nil {
			return nil, readErr
		}
		decoded := make([]map[string]any, 0, len(raw))
		for _, data := range raw {
			sum := sha256.Sum256(data)
			decoded = append(decoded, map[string]any{"_ipa_profile_hash": hex.EncodeToString(sum[:])})
		}
		if refreshReceiptPresent(prior, decoded) {
			for i := range baseline {
				baseline[i].Expires = prior.Expiries[i]
			}
		}
	}
	notify(.05, "Checking installed app and signing identity")
	apps, err := io.inventory(ctx)
	if err != nil {
		return nil, err
	}
	if !matchingRefreshApp(binding, apps) {
		return nil, errProfileRefreshUnsupported
	}
	r, err := client.Request(ctx, session, "listAllDevelopmentCerts", nil, binding.Team)
	if err != nil {
		return nil, err
	}
	certs, err := recordList(r, "certificates")
	if err != nil {
		return nil, err
	}
	active := false
	for _, c := range certs {
		if cert := validCert(c, now); cert != nil && bytes.Equal(cert.Raw, binding.Certificate) {
			active = true
		}
	}
	if !active {
		return nil, errProfileRefreshUnsupported
	}
	r, err = client.Request(ctx, session, "listAppIds", nil, binding.Team)
	if err != nil {
		return nil, err
	}
	registrations, err := recordList(r, "appIds")
	if err != nil {
		return nil, err
	}
	required := map[string]bool{}
	for _, member := range binding.Members {
		required[member.Registration] = true
	}
	appIDs := map[string]string{}
	for _, app := range registrations {
		identifier, id := stringField(app, "identifier"), stringField(app, "appIdId")
		// Unrelated registrations, including legacy duplicate/empty entries, cannot
		// make this app's exact registration ambiguous. Identical rows are harmless.
		if !required[identifier] {
			continue
		}
		if previous, duplicate := appIDs[identifier]; duplicate && previous != id {
			return nil, fmt.Errorf("%w: the app has conflicting developer registrations", errProfileRefreshUnsupported)
		}
		appIDs[identifier] = id
	}
	profiles := make([][]byte, 0, len(binding.Members))
	receipt := &profileRefreshReceipt{Account: session.Username, Expires: certificate.NotAfter}
	seen := map[string]bool{}
	// A profile cannot keep code valid beyond its original signing certificate.
	oldExpiry := certificate.NotAfter
	for _, member := range baseline {
		if !bundlePattern.MatchString(member.BundleID) || !bundlePattern.MatchString(member.Registration) || seen[member.BundleID] || (member.BundleID != binding.BundleID && !strings.HasPrefix(member.BundleID, binding.BundleID+".")) {
			return nil, errProfileRefreshUnsupported
		}
		seen[member.BundleID] = true
		id := appIDs[member.Registration]
		if !validText(id) {
			return nil, errProfileRefreshUnsupported
		}
		notify(.2, "Renewing app signing profiles")
		response, requestErr := client.Request(ctx, session, "downloadTeamProvisioningProfile", map[string]any{"appIdId": id}, binding.Team)
		if requestErr != nil {
			return nil, requestErr
		}
		raw, ok := mapField(response, "provisioningProfile")["encodedProfile"].([]byte)
		if !ok || len(raw) == 0 || len(raw) > 16<<20 {
			return nil, failure("Developer service returned an invalid refresh profile")
		}
		p, decodeErr := io.decode(raw)
		if decodeErr != nil {
			return nil, failure("Refresh profile CMS integrity did not verify")
		}
		// Apple may create this profile during the request; validate against the
		// current time, not the earlier operation-start timestamp.
		if err = validateRefreshProfile(p, binding, member, udid, time.Now()); err != nil {
			return nil, err
		}
		expiry := p["ExpirationDate"].(time.Time)
		if receipt.Expires.IsZero() || expiry.Before(receipt.Expires) {
			receipt.Expires = expiry
		}
		if oldExpiry.IsZero() || member.Expires.Before(oldExpiry) {
			oldExpiry = member.Expires
		}
		sum := sha256.Sum256(raw)
		receipt.Hashes = append(receipt.Hashes, hex.EncodeToString(sum[:]))
		receipt.Expiries = append(receipt.Expiries, expiry)
		profiles = append(profiles, raw)
	}
	// A portal may return the same profile. Do not fabricate a refresh timestamp.
	if !receipt.Expires.After(oldExpiry) {
		return nil, nil
	}
	// Recheck the app after portal work, before submitting anything to the phone.
	apps, err = io.inventory(ctx)
	if err != nil {
		return nil, err
	}
	if !matchingRefreshApp(binding, apps) {
		return nil, errProfileRefreshUnsupported
	}
	for i, raw := range profiles {
		if err = ctx.Err(); err != nil {
			if i > 0 {
				return nil, fmt.Errorf("%w: %v", errProfileRefreshUnconfirmed, err)
			}
			return nil, err
		}
		notify(.65, "Applying renewed signing profiles")
		err = io.install(ctx, raw)
		if err != nil {
			if io.rejected != nil && io.rejected(err) {
				return nil, fmt.Errorf("%w: this iPhone requires reinstallation", errProfileRefreshUnsupported)
			}
			// A connection failure can occur after iOS accepted the request. Attempt
			// independent readback, but never silently launch a second signing operation.
			break
		}
	}
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%w: %v", errProfileRefreshUnconfirmed, ctx.Err())
	}
	notify(.9, "Confirming renewed profiles on iPhone")
	rawProfiles, readErr := io.profiles(ctx)
	if readErr != nil {
		return nil, errProfileRefreshUnconfirmed
	}
	found := map[string]bool{}
	for _, raw := range rawProfiles {
		sum := sha256.Sum256(raw)
		found[hex.EncodeToString(sum[:])] = true
	}
	for _, hash := range receipt.Hashes {
		if !found[hash] {
			return nil, errProfileRefreshUnconfirmed
		}
	}
	apps, err = io.inventory(ctx)
	if err != nil || !matchingRefreshApp(binding, apps) {
		return nil, errProfileRefreshUnconfirmed
	}
	receipt.Refreshed = time.Now().UTC()
	notify(1, "App refreshed without reinstalling")
	return receipt, nil
}

func profileExpiry(profile map[string]any) time.Time {
	expiry, _ := profile["ExpirationDate"].(time.Time)
	return expiry
}
