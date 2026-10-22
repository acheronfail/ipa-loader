//go:build (darwin && !ios) || linux || windows

package platform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"ipa-loader/app/internal/apple"
	"ipa-loader/app/internal/bootstrap"
	"ipa-loader/app/internal/ipa"
	"ipa-loader/app/internal/mobiledevice"
	"ipa-loader/app/internal/signing"
	"os"
	"path/filepath"
	"runtime"
)

// BootstrapLoader installs the packaged iOS target and commits its private setup
// only after both installation and the original IPA transfer are verified.
func BootstrapLoader(ctx context.Context, client *apple.Client, session *apple.Session, team string, device Device, progress func(Progress)) (result Result, err error) {
	notify := func(f float64, s string) {
		if progress != nil {
			progress(Progress{f, s})
		}
	}
	notify(0, "Checking IPA Loader for iOS")
	filename, err := LoaderIPAPath()
	if err != nil {
		return result, err
	}
	teams, err := client.Teams(ctx, session)
	if err != nil {
		return result, err
	}
	builtInVPN := false
	for _, candidate := range teams {
		if candidate.ID == team {
			builtInVPN = candidate.LimitKnown && candidate.AppIDsUnlimited
		}
	}
	filename, err = loaderIPAForAccount(filename, builtInVPN)
	if err != nil {
		return result, err
	}
	info, err := ipa.Inspect(filename)
	if err != nil {
		return result, err
	}
	if info.BundleID != bootstrap.BundleID {
		return result, errors.New("The packaged iOS IPA is not IPA Loader")
	}
	// Validate pairing before account mutations or installing anything.
	pair, err := mobiledevice.ExportPairRecord(ctx, device.UDID)
	if err != nil {
		return result, err
	}
	defer clear(pair)
	result, err = Sideload(ctx, client, session, team, filename, device, func(p Progress) { notify(p.Fraction*.75, p.Message) })
	if err != nil {
		return result, err
	}
	root, err := os.UserConfigDir()
	if runtime.GOOS == "windows" {
		root = os.Getenv("LOCALAPPDATA")
	}
	if err != nil {
		return result, err
	}
	identity, err := (signing.IdentityVault{Dir: filepath.Join(root, "ipa-loader", "signing")}).Load(team)
	if err != nil {
		return result, err
	}
	key := x509.MarshalPKCS1PrivateKey(identity.PrivateKey)
	defer clear(key)
	f, err := os.Open(filename)
	if err != nil {
		return result, err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return result, err
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, f); err != nil {
		return result, err
	}
	if _, err = f.Seek(0, 0); err != nil {
		return result, err
	}
	cfg := bootstrap.Config{Account: session.Username, Version: 1, UDID: device.UDID, Team: team, InstalledBundleID: result.BundleID, Address: bootstrap.DefaultAddress, IPASHA256: hex.EncodeToString(hash.Sum(nil)), PairRecord: pair, PrivateKey: key, Certificate: identity.Certificate.Raw}
	if err = cfg.Validate(); err != nil {
		return result, err
	}
	notify(.76, "Saving IPA Loader's self-refresh package")
	if err = mobiledevice.WriteBootstrapDocument(ctx, device.UDID, result.BundleID, bootstrap.SelfIPA, f, stat.Size(), func(n, total int64) { notify(.76+.18*float64(n)/float64(total), "Transferring self-refresh package") }); err != nil {
		return result, bootstrapTransferError(err)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return result, err
	}
	defer clear(raw)
	notify(.95, "Transferring and verifying private pairing and signing credentials")
	if err = mobiledevice.WriteBootstrapDocument(ctx, device.UDID, result.BundleID, bootstrap.ConfigFile, bytes.NewReader(raw), int64(len(raw)), nil); err != nil {
		return result, bootstrapTransferError(err)
	}
	result.CompletionMessage = "IPA Loader installed and configured. Open it on your iPhone, connect LocalDevVPN, and sign in with the same Apple Account."
	if builtInVPN {
		result.CompletionMessage = "IPA Loader installed and configured. Open it on your iPhone, sign in with the same Apple Account, and allow its built-in VPN configuration."
	}
	notify(1, result.CompletionMessage)
	return result, nil
}
func loaderIPAForAccount(freeIPA string, paid bool) (string, error) {
	if !paid {
		return freeIPA, nil
	}
	filename := filepath.Join(filepath.Dir(freeIPA), "IPA-Loader-Paid-Accounts.ipa")
	if st, err := os.Stat(filename); err != nil || !st.Mode().IsRegular() {
		return "", errors.New("The paid-account iOS package is missing: include IPA-Loader-Paid-Accounts.ipa with this desktop release")
	}
	return filename, nil
}
func bootstrapTransferError(err error) error {
	return errors.Join(errors.New("IPA Loader was installed, but setup transfer did not finish. Keep it closed and retry Install IPA Loader"), err)
}
func LoaderIPAPath() (string, error) {
	if configured := os.Getenv("IPA_LOADER_IOS_IPA"); configured != "" {
		if !filepath.IsAbs(configured) {
			return "", errors.New("IPA_LOADER_IOS_IPA must be absolute")
		}
		return configured, nil
	}
	root, err := loaderRuntimeRoot()
	if err != nil {
		return "", err
	}
	for _, p := range []string{filepath.Join(root, "ios", "IPA-Loader-Free-Accounts.ipa"), filepath.Join("build", "ios", "IPA-Loader-Free-Accounts.ipa")} {
		if stat, err := os.Stat(p); err == nil && stat.Mode().IsRegular() {
			return filepath.Abs(p)
		}
	}
	return "", errors.New("The iOS package is missing. Build it on macOS with just ios, then include ios/IPA-Loader-Free-Accounts.ipa with this desktop release")
}
