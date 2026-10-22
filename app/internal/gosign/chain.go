package gosign

import (
	"bytes"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
)

// Apple public CA certificates present in the hash-pinned zsign reference
// revision 9299685bab7ef99827e06e5dfda93af747386590 (MIT). These are public
// issuer material, never development identities or private signing material.
//
//go:embed apple-ca.txt
var appleCA []byte

func issuerChain(leaf *x509.Certificate) ([]*x509.Certificate, error) {
	var pool []*x509.Certificate
	data := appleCA
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, errors.New("invalid embedded CA bundle")
		}
		data = rest
		c, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			return nil, e
		}
		pool = append(pool, c)
	}
	var chain []*x509.Certificate
	seen := map[string]bool{}
	for n := 0; n < 5; n++ {
		if bytes.Equal(leaf.RawIssuer, leaf.RawSubject) {
			return chain, nil
		}
		var parent *x509.Certificate
		for _, c := range pool {
			if bytes.Equal(leaf.RawIssuer, c.RawSubject) && leaf.CheckSignatureFrom(c) == nil {
				parent = c
				break
			}
		}
		if parent == nil {
			return nil, errors.New("unsupported development certificate issuer")
		}
		if seen[string(parent.Raw)] {
			return nil, errors.New("cyclic issuer chain")
		}
		seen[string(parent.Raw)] = true
		chain = append(chain, parent)
		leaf = parent
	}
	return nil, errors.New("issuer chain exceeds bounds")
}
