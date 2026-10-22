package platform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"howett.net/plist"
	"ipa-loader/app/internal/codesignverify"
)

// Capture the signed app + complete extension graph independently of its IPA.
// A full signing operation can then fall back to its package, but renewal does
// not need that package or access to a private signing key.
func captureRefreshBinding(ctx context.Context, path string, certificate []byte) (*refreshBinding, error) {
	if len(certificate) == 0 || len(certificate) > 16<<10 {
		return nil, errProfileRefreshUnsupported
	}
	if _, err := codesignverify.VerifyBundle(ctx, path, codesignverify.Options{CertificateDER: certificate}); err != nil {
		return nil, err
	}
	readInfo := func(path string) (map[string]any, error) {
		raw, err := readLimited(filepath.Join(path, "Info.plist"), 1<<20)
		if err != nil {
			return nil, err
		}
		return dictionary(raw)
	}
	main, err := readInfo(path)
	if err != nil {
		return nil, err
	}
	binding := &refreshBinding{BundleID: stringField(main, "CFBundleIdentifier"), Version: stringField(main, "CFBundleShortVersionString"), Build: stringField(main, "CFBundleVersion"), Certificate: append([]byte(nil), certificate...)}
	paths, err := refreshMemberPaths(path)
	if err != nil {
		return nil, err
	}
	spent := 0
	for _, memberPath := range paths {
		info, err := readInfo(memberPath)
		if err != nil {
			return nil, err
		}
		id := stringField(info, "CFBundleIdentifier")
		executable := stringField(info, "CFBundleExecutable")
		if !bundlePattern.MatchString(id) || filepath.Base(executable) != executable || !validText(executable) || strings.ContainsAny(executable, "/\\:") {
			return nil, errProfileRefreshUnsupported
		}
		code, err := readLimited(filepath.Join(memberPath, executable), 512<<20)
		if err != nil {
			return nil, err
		}
		slices, err := machSlices(code)
		if err != nil {
			return nil, err
		}
		ent, err := consistentSliceEntitlements(slices)
		if err != nil {
			return nil, err
		}
		profileData, err := decodeProfile(filepath.Join(memberPath, "embedded.mobileprovision"))
		if err != nil {
			return nil, err
		}
		profile, err := dictionary(profileData)
		if err != nil {
			return nil, err
		}
		prefix := textList(profile["ApplicationIdentifierPrefix"])
		teams := textList(profile["TeamIdentifier"])
		if len(prefix) != 1 || len(teams) != 1 {
			return nil, errProfileRefreshUnsupported
		}
		if binding.Team == "" {
			binding.Team = teams[0]
		}
		if teams[0] != binding.Team || stringField(ent, "com.apple.developer.team-identifier") != binding.Team {
			return nil, errProfileRefreshUnsupported
		}
		appID := stringField(mapField(profile, "Entitlements"), "application-identifier")
		if !strings.HasPrefix(appID, prefix[0]+".") || strings.Contains(appID, "*") || !profileAuthorizes(mapField(profile, "Entitlements"), ent) {
			return nil, errProfileRefreshUnsupported
		}
		embedded, readErr := readLimited(filepath.Join(memberPath, "embedded.mobileprovision"), 16<<20)
		if readErr != nil {
			return nil, readErr
		}
		sum := sha256.Sum256(embedded)
		member := refreshMember{EmbeddedProfileHash: hex.EncodeToString(sum[:]), BundleID: id, Registration: strings.TrimPrefix(appID, prefix[0]+"."), Expires: profileExpiry(profile)}
		if !bundlePattern.MatchString(member.Registration) || member.Expires.IsZero() {
			return nil, errProfileRefreshUnsupported
		}
		member.Entitlements, err = plist.Marshal(ent, plist.XMLFormat)
		if err != nil {
			return nil, err
		}
		spent += len(member.Entitlements)
		if spent > 256<<10 {
			return nil, errProfileRefreshUnsupported
		}
		binding.Members = append(binding.Members, member)
	}
	return binding, nil
}

// Reject provisioning-bearing bundles outside the supported direct extension
// graph instead of silently renewing only part of an installation.
func refreshMemberPaths(root string) ([]string, error) {
	extensions, err := filepath.Glob(filepath.Join(root, "PlugIns", "*.appex"))
	if err != nil || len(extensions) > 31 {
		return nil, errProfileRefreshUnsupported
	}
	paths := append([]string{root}, extensions...)
	known := map[string]bool{}
	for _, path := range paths {
		known[path] = true
	}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && (filepath.Ext(path) == ".appex" || filepath.Ext(path) == ".app") && !known[path] {
			return errProfileRefreshUnsupported
		}
		if !entry.IsDir() && entry.Name() == "embedded.mobileprovision" && !known[filepath.Dir(path)] {
			return errProfileRefreshUnsupported
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return paths, nil
}

func sameRefreshCode(a, b *refreshBinding) bool {
	if a == nil || b == nil || a.BundleID != b.BundleID || a.Team != b.Team || a.Version != b.Version || a.Build != b.Build || !bytes.Equal(a.Certificate, b.Certificate) || len(a.Members) != len(b.Members) {
		return false
	}
	for i, member := range a.Members {
		other := b.Members[i]
		if member.EmbeddedProfileHash != other.EmbeddedProfileHash || member.BundleID != other.BundleID || member.Registration != other.Registration || !bytes.Equal(member.Entitlements, other.Entitlements) {
			return false
		}
	}
	return true
}

// A bundle embedded in IPA Loader's own sandbox can be verified directly.
// Third-party apps require a signing binding saved at confirmed installation.
func selfRefreshBinding(ctx context.Context, path string) (*refreshBinding, error) {
	raw, err := decodeProfile(filepath.Join(path, "embedded.mobileprovision"))
	if err != nil {
		return nil, err
	}
	profile, err := dictionary(raw)
	if err != nil {
		return nil, err
	}
	certs, _ := profile["DeveloperCertificates"].([]any)
	if len(certs) == 0 || len(certs) > 16 {
		return nil, errProfileRefreshUnsupported
	}
	for _, value := range certs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if certificate, ok := value.([]byte); ok {
			if binding, err := captureRefreshBinding(ctx, path, certificate); err == nil {
				return binding, nil
			}
		}
	}
	return nil, errors.New("The installed app's signing identity could not be verified")
}
func readSelfInfo(path string) (map[string]any, error) {
	raw, err := os.ReadFile(filepath.Join(path, "Info.plist"))
	if err != nil {
		return nil, err
	}
	return dictionary(raw)
}

func bindingMatchesEmbeddedProfile(path string, binding *refreshBinding) bool {
	if binding == nil || len(binding.Members) == 0 || binding.Members[0].EmbeddedProfileHash == "" {
		return false
	}
	raw, err := readLimited(filepath.Join(path, "embedded.mobileprovision"), 16<<20)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]) == binding.Members[0].EmbeddedProfileHash
}
