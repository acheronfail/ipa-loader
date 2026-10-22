//go:build ios

package platform

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"ipa-loader/app/internal/apple"
	"ipa-loader/app/internal/bootstrap"
	"ipa-loader/app/internal/iosnative"
	"ipa-loader/app/internal/mobiledevice"
	"ipa-loader/app/internal/securestore"
	"ipa-loader/app/internal/signing"
	"os"
	"path/filepath"
	"sync"
)

var iosSetup struct {
	sync.RWMutex
	config *bootstrap.Config
}

func iosConfigPath() string {
	root, _ := os.UserConfigDir()
	return filepath.Join(root, "ipa-loader", "bootstrap.secret")
}
func selfIPAPath() string { return filepath.Join(iosnative.Home(), "Documents", bootstrap.SelfIPA) }
func verifySelfIPA(c bootstrap.Config) error {
	f, err := os.Open(selfIPAPath())
	if err != nil {
		return errors.New("Self-refresh package is missing. Run Install IPA Loader on your computer again")
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != c.IPASHA256 {
		return errors.New("Self-refresh package changed. Run Install IPA Loader on your computer again")
	}
	return nil
}

// InitializeIOS consumes the final bootstrap envelope only after it matches this
// app, the original refresh IPA, and the retained signing identity. Secrets move
// to Keychain; the transfer file is then removed from Documents.
func InitializeIOS() error {
	incoming := filepath.Join(iosnative.Home(), "Documents", bootstrap.ConfigFile)
	var raw []byte
	stat, err := os.Lstat(incoming)
	fromDesktop := err == nil
	if err == nil {
		if !stat.Mode().IsRegular() || stat.Size() > 2<<20 {
			return errors.New("Invalid desktop setup transfer")
		}
		raw, err = os.ReadFile(incoming)
	}
	if os.IsNotExist(err) {
		raw, err = securestore.Read(iosConfigPath(), 2<<20)
	}
	if err != nil {
		return err
	}
	defer clear(raw)
	if len(raw) == 0 {
		return errors.New("Finish setup using Install IPA Loader in the desktop app, then reopen IPA Loader")
	}
	c, err := bootstrap.Decode(raw)
	if err != nil {
		return err
	}
	if c.InstalledBundleID != iosnative.BundleID() {
		c.Clear()
		return errors.New("Setup belongs to a different IPA Loader installation")
	}
	if err = verifySelfIPA(c); err != nil {
		c.Clear()
		return err
	}
	key, err := x509.ParsePKCS1PrivateKey(c.PrivateKey)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(c.Certificate)
	if err != nil {
		return err
	}
	root, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	if fromDesktop {
		if err = (signing.IdentityVault{Dir: filepath.Join(root, "ipa-loader", "signing")}).AdoptBootstrap(c.Team, key, cert); err != nil {
			return err
		}
	}
	if err = mobiledevice.ConfigureDirectDevice(mobiledevice.DirectDevice{UDID: c.UDID, Address: c.Address, PairRecord: c.PairRecord, BuiltInVPN: iosnative.HasVPN()}); err != nil {
		return err
	}
	if fromDesktop {
		if err = securestore.Write(iosConfigPath(), raw); err != nil {
			return err
		}
		if err = os.Remove(incoming); err != nil {
			return err
		}
	}
	iosSetup.Lock()
	iosSetup.config = &c
	iosSetup.Unlock()
	return nil
}
func BootstrapLoader(ctx context.Context, client *apple.Client, s *apple.Session, team string, d Device, progress func(Progress)) (Result, error) {
	iosSetup.RLock()
	c := iosSetup.config
	iosSetup.RUnlock()
	if c == nil {
		return Result{}, errors.New("Run desktop setup before refreshing IPA Loader")
	}
	if team != c.Team || d.UDID != c.UDID {
		return Result{}, errors.New("Refresh IPA Loader using its original developer team and device")
	}
	if err := verifySelfIPA(*c); err != nil {
		return Result{}, err
	}
	return Sideload(ctx, client, s, team, selfIPAPath(), d, progress)
}

// SetIOSDeviceAddress permits matching a changed LocalDevVPN Device IP.
func SetIOSDeviceAddress(address string) error {
	iosSetup.Lock()
	defer iosSetup.Unlock()
	if iosSetup.config == nil {
		return errors.New("Desktop setup is incomplete")
	}
	c := *iosSetup.config
	c.Address = address
	if err := c.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	defer clear(raw)
	if err = securestore.Write(iosConfigPath(), raw); err != nil {
		return err
	}
	if err = mobiledevice.ConfigureDirectDevice(mobiledevice.DirectDevice{UDID: c.UDID, Address: c.Address, PairRecord: c.PairRecord, BuiltInVPN: iosnative.HasVPN()}); err != nil {
		return err
	}
	iosSetup.config = &c
	return nil
}

func IOSDeviceAddress() string {
	iosSetup.RLock()
	defer iosSetup.RUnlock()
	if iosSetup.config == nil {
		return bootstrap.DefaultAddress
	}
	return iosSetup.config.Address
}

func IsIOSDevice(device Device) bool {
	iosSetup.RLock()
	defer iosSetup.RUnlock()
	return iosSetup.config != nil && device.UDID == iosSetup.config.UDID
}
