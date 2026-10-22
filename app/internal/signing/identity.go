//go:build windows || linux || darwin

// Package signing provides signing identity storage and independently
// checked native signing boundaries.
package signing

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"ipa-loader/app/internal/securestore"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var ErrNoIdentity = errors.New("No active signing identity is available")
var teamIDPattern = regexp.MustCompile(`^[A-Z0-9]{10}$`)

// Match platform.validCert's manual-installation selection margin. This is
// evaluated only when a user starts signing, never by an automatic refresh job.
const identityRenewalMargin = 24 * time.Hour

func needsIdentityRenewal(certificate *x509.Certificate, now time.Time) bool {
	return certificate.NotAfter.Sub(now) < identityRenewalMargin
}

// IdentityVault keeps signing keys and pending CSR recovery data encrypted for
// the local user. It never revokes or deletes Apple certificates.
type IdentityVault struct{ Dir string }

type identityRecord struct {
	Version     int    `json:"version"`
	Team        string `json:"team"`
	PrivateKey  []byte `json:"private_key"`
	CSR         []byte `json:"csr"`
	RequestID   string `json:"request_id"`
	Certificate []byte `json:"certificate,omitempty"`
	// Nil is a legacy/uncertain submission and must never be resent.
	Submitted *bool `json:"submitted,omitempty"`
}

// PendingIdentity contains one retained signing request. Prepare returns the
// same request until its matching certificate is saved, including after restart.
type PendingIdentity struct {
	CSR             string
	RequestID       string
	Created         bool
	NeedsSubmission bool
}

func (PendingIdentity) String() string   { return "Pending signing identity (private)" }
func (PendingIdentity) GoString() string { return "Pending signing identity (private)" }

type Identity struct {
	Team        string
	PrivateKey  *rsa.PrivateKey
	Certificate *x509.Certificate
}

func (Identity) String() string   { return "signing identity (private)" }
func (Identity) GoString() string { return "signing identity (private)" }

func (v IdentityVault) path(team string) (string, error) {
	if !teamIDPattern.MatchString(team) || !filepath.IsAbs(v.Dir) {
		return "", errors.New("Invalid signing storage location or team")
	}
	sum := sha256.Sum256([]byte(team))
	return filepath.Join(v.Dir, hex.EncodeToString(sum[:])+identitySuffix), nil
}

func (v IdentityVault) read(team string) (identityRecord, *rsa.PrivateKey, error) {
	path, err := v.path(team)
	if err != nil {
		return identityRecord{}, nil, err
	}
	data, err := securestore.Read(path, 65536)
	if err != nil {
		return identityRecord{}, nil, errors.New("Could not read retained signing material")
	}
	defer clear(data)
	if len(data) == 0 {
		return identityRecord{}, nil, ErrNoIdentity
	}
	var record identityRecord
	if json.Unmarshal(data, &record) != nil || record.Version != 1 || record.Team != team || len(record.RequestID) != 36 {
		return identityRecord{}, nil, errors.New("Retained signing material is invalid")
	}
	key, err := x509.ParsePKCS1PrivateKey(record.PrivateKey)
	if err != nil || key.N.BitLen() != 2048 || key.Validate() != nil {
		return identityRecord{}, nil, errors.New("Retained signing key is invalid")
	}
	csr, err := x509.ParseCertificateRequest(record.CSR)
	if err != nil || csr.CheckSignature() != nil {
		return identityRecord{}, nil, errors.New("Retained signing request is invalid")
	}
	pub, ok := csr.PublicKey.(*rsa.PublicKey)
	if !ok || pub.E != key.E || pub.N.Cmp(key.N) != 0 {
		return identityRecord{}, nil, errors.New("Retained signing request does not match its key")
	}
	return record, key, nil
}

func (v IdentityVault) write(record identityRecord) error {
	path, err := v.path(record.Team)
	if err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	defer clear(data)
	if err = securestore.Write(path, data); err != nil {
		return errors.New("Could not protect signing material")
	}
	return nil
}

// Prepare persists a new key and CSR before returning them to a portal caller.
// A retained key is always reused; malformed or unreadable storage fails closed.
func (v IdentityVault) Prepare(team string) (PendingIdentity, error) {
	unlock, err := v.locked(team)
	if err != nil {
		return PendingIdentity{}, err
	}
	defer unlock()
	record, retainedKey, err := v.read(team)
	defer func() { clear(record.PrivateKey) }()
	created := false
	newRequest := errors.Is(err, ErrNoIdentity)
	if err == nil && len(record.Certificate) > 0 {
		certificate, certificateErr := identityCertificate(record, retainedKey)
		if certificateErr != nil {
			return PendingIdentity{}, certificateErr
		}
		now := time.Now()
		if now.Before(certificate.NotBefore) {
			return PendingIdentity{}, errors.New("Retained signing certificate is not valid yet")
		}
		if needsIdentityRenewal(certificate, now) {
			if err = v.archiveCompleted(record); err != nil {
				return PendingIdentity{}, err
			}
			newRequest = true
		}
	}
	if newRequest {
		created = true
		key, keyErr := rsa.GenerateKey(rand.Reader, 2048)
		if keyErr != nil {
			return PendingIdentity{}, keyErr
		}
		csr, csrErr := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "IPA Loader Development", Organization: []string{"IPA Loader"}}, SignatureAlgorithm: x509.SHA256WithRSA}, key)
		if csrErr != nil {
			return PendingIdentity{}, csrErr
		}
		var machine [16]byte
		if _, err = rand.Read(machine[:]); err != nil {
			return PendingIdentity{}, err
		}
		machine[6] = machine[6]&15 | 64
		machine[8] = machine[8]&63 | 128
		clear(record.PrivateKey)
		unsubmitted := false
		record = identityRecord{Version: 1, Team: team, PrivateKey: x509.MarshalPKCS1PrivateKey(key), CSR: csr, RequestID: fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", machine[0:4], machine[4:6], machine[6:8], machine[8:10], machine[10:16]), Submitted: &unsubmitted}
		err = v.write(record)
	}
	if err != nil {
		return PendingIdentity{}, err
	}
	return PendingIdentity{CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: record.CSR})), RequestID: record.RequestID, Created: created, NeedsSubmission: len(record.Certificate) == 0 && record.Submitted != nil && !*record.Submitted}, nil
}

func identityCertificate(record identityRecord, key *rsa.PrivateKey) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(record.Certificate)
	if err != nil {
		return nil, errors.New("Retained signing certificate is invalid")
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || pub.E != key.E || pub.N.Cmp(key.N) != 0 {
		return nil, errors.New("signing certificate does not match its retained private key")
	}
	for _, unit := range cert.Subject.OrganizationalUnit {
		if unit == record.Team {
			return cert, nil
		}
	}
	return nil, errors.New("signing certificate belongs to a different team")
}

func validateIdentity(record identityRecord, key *rsa.PrivateKey) (*x509.Certificate, error) {
	if len(record.Certificate) == 0 {
		return nil, ErrNoIdentity
	}
	cert, err := identityCertificate(record, key)
	if err != nil {
		return nil, err
	}
	if time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
		return nil, ErrNoIdentity
	}
	return cert, nil
}

// MarkSubmitted records uncertainty before any portal request can leave the
// process. Retrying a marked or legacy request never resubmits its CSR.
func (v IdentityVault) MarkSubmitted(team, requestID string) error {
	unlock, err := v.locked(team)
	if err != nil {
		return err
	}
	defer unlock()
	record, _, err := v.read(team)
	if err != nil {
		return err
	}
	defer clear(record.PrivateKey)
	if record.RequestID != requestID || len(record.Certificate) != 0 || record.Submitted == nil || *record.Submitted {
		return errors.New("signing request changed or may already have been submitted")
	}
	submitted := true
	record.Submitted = &submitted
	return v.write(record)
}

// MarkQuotaRejected permits reusing the same key and CSR only after Apple has
// explicitly rejected that submission with certificate-limit code 7460. Network
// failures and ambiguous responses must remain submitted and uncertain.
func (v IdentityVault) MarkQuotaRejected(team, requestID string, code int) error {
	if code != 7460 {
		return errors.New("Only an explicit certificate quota rejection permits retry")
	}
	unlock, err := v.locked(team)
	if err != nil {
		return err
	}
	defer unlock()
	record, _, err := v.read(team)
	if err != nil {
		return err
	}
	defer clear(record.PrivateKey)
	if record.RequestID != requestID || len(record.Certificate) != 0 || record.Submitted == nil || !*record.Submitted {
		return errors.New("signing request changed or has no rejected submission")
	}
	submitted := false
	record.Submitted = &submitted
	return v.write(record)
}

// Archive only a validated completed identity. Its encrypted history is durable
// before a new pending key replaces the active record; no certificate is revoked.
func (v IdentityVault) archiveCompleted(record identityRecord) error {
	directory := filepath.Join(v.Dir, "history")
	if err := securestore.EnsureDir(directory); err != nil {
		return errors.New("Could not prepare private signing identity history")
	}
	team := sha256.Sum256([]byte(record.Team))
	cert := sha256.Sum256(record.Certificate)
	path := filepath.Join(directory, hex.EncodeToString(team[:])+"-"+hex.EncodeToString(cert[:])+identitySuffix)
	body, err := json.Marshal(record)
	if err != nil {
		return err
	}
	defer clear(body)
	existing, err := securestore.Read(path, 65536)
	if err != nil {
		return errors.New("Could not inspect signing identity history")
	}
	defer clear(existing)
	if len(existing) > 0 {
		if !bytes.Equal(existing, body) {
			return errors.New("Signing identity history conflicts with retained material")
		}
		return nil
	}
	if err = securestore.Write(path, body); err != nil {
		return errors.New("Could not retain completed signing identity history")
	}
	return nil
}

// SaveCertificate activates only an unexpired certificate matching the retained
// key and team. The caller still validates Apple's portal/profile authorization.
func (v IdentityVault) SaveCertificate(team string, der []byte) error {
	unlock, err := v.locked(team)
	if err != nil {
		return err
	}
	defer unlock()
	record, key, err := v.read(team)
	if err != nil {
		return err
	}
	record.Certificate = der
	if _, err = validateIdentity(record, key); err != nil {
		return err
	}
	return v.write(record)
}

// Load returns a currently usable identity without generating any key or CSR.
func (v IdentityVault) Load(team string) (Identity, error) {
	record, key, err := v.read(team)
	if err != nil {
		return Identity{}, err
	}
	cert, err := validateIdentity(record, key)
	if err != nil {
		return Identity{}, err
	}
	return Identity{Team: team, PrivateKey: key, Certificate: cert}, nil
}

// Fingerprint follows the existing platform's uppercase SHA-1 certificate ID.
func Fingerprint(der []byte) string {
	sum := sha1.Sum(der)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// AdoptBootstrap imports the signing identity supplied by desktop setup.
func (v IdentityVault) AdoptBootstrap(team string, key *rsa.PrivateKey, cert *x509.Certificate) error {
	if key == nil || cert == nil || key.Validate() != nil || key.N.BitLen() != 2048 {
		return errors.New("Invalid bootstrap signing identity")
	}
	unlock, err := v.locked(team)
	if err != nil {
		return err
	}
	defer unlock()
	existing, existingKey, err := v.read(team)
	defer clear(existing.PrivateKey)
	if err == nil {
		if existingKey.N.Cmp(key.N) == 0 && bytes.Equal(existing.Certificate, cert.Raw) {
			return nil
		}
		if _, err = identityCertificate(existing, existingKey); err != nil {
			return errors.New("Retained signing request is incomplete; finish or recover it before desktop setup")
		}
		// Validate the incoming identity before archiving or replacing anything.
		candidate := identityRecord{Team: team, Certificate: cert.Raw}
		if _, err = validateIdentity(candidate, key); err != nil {
			return err
		}
		if err = v.archiveCompleted(existing); err != nil {
			return err
		}
	} else if !errors.Is(err, ErrNoIdentity) {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "IPA Loader Development"}, SignatureAlgorithm: x509.SHA256WithRSA}, key)
	if err != nil {
		return err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	nonce[6] = nonce[6]&15 | 64
	nonce[8] = nonce[8]&63 | 128
	submitted := true
	record := identityRecord{Version: 1, Team: team, PrivateKey: x509.MarshalPKCS1PrivateKey(key), CSR: csr, Certificate: cert.Raw, RequestID: fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", nonce[:4], nonce[4:6], nonce[6:8], nonce[8:10], nonce[10:]), Submitted: &submitted}
	defer clear(record.PrivateKey)
	if _, err = identityCertificate(record, key); err != nil {
		return err
	}
	return v.write(record)
}
