//go:build windows || linux || darwin

package signing

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"howett.net/plist"
	"ipa-loader/app/internal/codesignverify"
	"ipa-loader/app/internal/gosign"
)

// Tool signs exactly one code object in Go. Provisioning
// and identity policy remain the caller's responsibility. Profile supplies team
// metadata for libraries; executable bundles use their own embedded profile.
type Tool struct {
	Profile    string
	Identifier string
	// Optional issuer chain, leaf issuer first. Native Apple identities normally
	// use the embedded matching Apple issuer chain. Explicit chains are validated
	// against the leaf before inclusion in the CMS signature.
	CertificateChainPEM []byte
}

func validateChain(leaf *x509.Certificate, data []byte) error {
	if len(data) == 0 || len(data) > 1<<20 {
		return errors.New("Invalid explicit signing certificate chain")
	}
	for len(bytes.TrimSpace(data)) > 0 {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return errors.New("Invalid explicit signing certificate chain")
		}
		issuer, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !bytes.Equal(leaf.RawIssuer, issuer.RawSubject) || leaf.CheckSignatureFrom(issuer) != nil {
			return errors.New("Explicit signing certificate chain does not issue the leaf")
		}
		leaf, data = issuer, rest
	}
	return nil
}

func nestedCodeSnapshot(root string) (map[string][32]byte, error) {
	return nestedCodeSnapshotContext(context.Background(), root)
}

type signingContextReader struct {
	ctx   context.Context
	input io.Reader
}

func (r signingContextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.input.Read(data)
}

func nestedCodeSnapshotContext(ctx context.Context, root string) (map[string][32]byte, error) {
	snapshot := map[string][32]byte{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil || path == root {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("Linked signing input is unsupported")
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		nested := strings.EqualFold(filepath.Ext(path), ".dylib")
		parts := strings.Split(rel, string(filepath.Separator))
		for _, part := range parts[:len(parts)-1] {
			switch strings.ToLower(filepath.Ext(part)) {
			case ".appex", ".framework", ".app":
				nested = true
			}
		}
		if !nested {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		hash := sha256.New()
		_, err = io.Copy(hash, signingContextReader{ctx, file})
		file.Close()
		if err != nil {
			return err
		}
		var sum [32]byte
		copy(sum[:], hash.Sum(nil))
		snapshot[rel] = sum
		return nil
	})
	return snapshot, err
}

// Sign preserves separately signed children, applies exact caller-provided
// entitlements and requires independent signature/resource verification before
// returning success. Private keys remain in memory during signing.
func (tool Tool) Sign(ctx context.Context, path string, keyPEM, certDER []byte, entitlementsPath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !filepath.IsAbs(path) || tool.Identifier == "" || strings.ContainsAny(tool.Identifier, "\x00\r\n") {
		return errors.New("Configure an absolute signing object path")
	}
	block, rest := pem.Decode(keyPEM)
	if block == nil || len(rest) != 0 {
		return errors.New("Invalid signing private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return errors.New("Invalid signing private key")
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return errors.New("Invalid signing certificate")
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || pub.E != key.E || pub.N.Cmp(key.N) != 0 {
		return errors.New("signing certificate and private key do not match")
	}
	if len(tool.CertificateChainPEM) > 0 {
		if err = validateChain(cert, tool.CertificateChainPEM); err != nil {
			return err
		}
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Could not inspect signing input")
	}
	profile := tool.Profile
	var expectedEntitlements []byte
	if entitlementsPath != "" {
		if !filepath.IsAbs(entitlementsPath) {
			return errors.New("Signing entitlements require an absolute path")
		}
		expectedEntitlements, err = os.ReadFile(entitlementsPath)
		if err != nil || len(expectedEntitlements) == 0 || len(expectedEntitlements) > 1<<20 {
			return errors.New("Could not read exact signing entitlements")
		}
	}
	var before map[string][32]byte
	if info.IsDir() {
		metadata, readErr := os.ReadFile(filepath.Join(path, "Info.plist"))
		var fields map[string]any
		if readErr != nil || len(metadata) > 1<<20 {
			return errors.New("Could not inspect signing bundle metadata")
		}
		if _, err = plist.Unmarshal(metadata, &fields); err != nil || fields["CFBundleIdentifier"] != tool.Identifier {
			return errors.New("Signing bundle identifier differs from its resolved identity")
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".app", ".appex":
			profile = filepath.Join(path, "embedded.mobileprovision")
			if len(expectedEntitlements) == 0 {
				return errors.New("Executable bundle requires explicit validated entitlements")
			}
		case ".framework":
			if len(expectedEntitlements) != 0 {
				return errors.New("Frameworks must not inherit app entitlements")
			}
		default:
			return errors.New("Unsupported signing bundle")
		}
		before, err = nestedCodeSnapshotContext(ctx, path)
		if err != nil {
			return err
		}
	} else if !info.Mode().IsRegular() || len(expectedEntitlements) != 0 {
		return errors.New("Embedded libraries require a regular file without app entitlements")
	}
	if !filepath.IsAbs(profile) {
		return errors.New("signing requires a validated provisioning profile")
	}
	var chain []*x509.Certificate
	remaining := tool.CertificateChainPEM
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			return errors.New("invalid signing chain")
		}
		c, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			return e
		}
		chain = append(chain, c)
		remaining = bytes.TrimSpace(rest)
	}
	if err = gosign.Sign(ctx, path, gosign.Identity{Key: key, Certificate: cert, Chain: chain}, gosign.Options{Identifier: tool.Identifier, Entitlements: expectedEntitlements}); err != nil {
		return err
	}
	if info.IsDir() {
		after, err := nestedCodeSnapshotContext(ctx, path)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil || len(before) != len(after) {
			return errors.New("Signing changed separately signed embedded code")
		}
		for path, sum := range before {
			if after[path] != sum {
				return errors.New("Signing changed separately signed embedded code")
			}
		}
	}
	options := codesignverify.Options{CertificateDER: certDER, Identifier: tool.Identifier, Entitlements: expectedEntitlements, RequireNoEntitlements: len(expectedEntitlements) == 0}
	if info.IsDir() {
		_, err = codesignverify.VerifyBundle(ctx, path, options)
	} else {
		_, err = codesignverify.VerifyBinary(ctx, path, options)
	}
	return err
}
