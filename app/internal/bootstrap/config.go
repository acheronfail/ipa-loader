// Package bootstrap defines the private desktop-to-device setup envelope.
package bootstrap

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
)

const BundleID = "org.ipaloader.ios"
const ConfigFile = "IPALoaderBootstrap.json"
const SelfIPA = "IPALoader.ipa"
const DefaultAddress = "10.7.0.1"

var teamPattern = regexp.MustCompile(`^[A-Z0-9]{10}$`)
var loaderPattern = regexp.MustCompile(`^` + regexp.QuoteMeta(BundleID) + `(?:\.[A-Z0-9]{10})?$`)

func IsLoaderBundleID(id string) bool { return loaderPattern.MatchString(id) }

type Config struct {
	Version                                           int
	Account                                           string
	UDID, Team, InstalledBundleID, Address, IPASHA256 string
	PairRecord, PrivateKey, Certificate               []byte
}

func (Config) String() string   { return "Private IPA Loader bootstrap" }
func (Config) GoString() string { return "Private IPA Loader bootstrap" }
func (c *Config) Clear()        { clear(c.PairRecord); clear(c.PrivateKey) }
func (c Config) Validate() error {
	bad := errors.New("Invalid IPA Loader bootstrap data; run desktop setup again")
	if len(c.Account) > 320 {
		return bad
	}
	if c.Version != 1 || !teamPattern.MatchString(c.Team) || c.UDID == "" || len(c.UDID) > 128 {
		return bad
	}
	if c.InstalledBundleID != BundleID && c.InstalledBundleID != BundleID+"."+c.Team {
		return bad
	}
	ip, err := netip.ParseAddr(c.Address)
	if err != nil || !ip.Is4() || !ip.IsPrivate() {
		return bad
	}
	digest, err := hex.DecodeString(c.IPASHA256)
	if err != nil || len(digest) != 32 {
		return bad
	}
	if len(c.PairRecord) == 0 || len(c.PairRecord) > 1<<20 {
		return bad
	}
	key, err := x509.ParsePKCS1PrivateKey(c.PrivateKey)
	if err != nil || key.Validate() != nil || key.N.BitLen() != 2048 {
		return bad
	}
	cert, err := x509.ParseCertificate(c.Certificate)
	if err != nil {
		return bad
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || pub.E != key.E || pub.N.Cmp(key.N) != 0 {
		return bad
	}
	for _, team := range cert.Subject.OrganizationalUnit {
		if team == c.Team {
			return nil
		}
	}
	return bad
}
func Decode(raw []byte) (Config, error) {
	var c Config
	if len(raw) > 2<<20 || json.Unmarshal(raw, &c) != nil {
		return c, errors.New("Could not read IPA Loader bootstrap data")
	}
	return c, c.Validate()
}
