// Package cms provides bounded pure-Go CMS decoding and cryptographic integrity
// verification. Certificate chain trust and profile authorization are separate.
package cms

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/smallstep/pkcs7"
)

// Canonical converts bounded BER containers to DER. Primitive signed payloads
// remain byte-for-byte intact. No generic unbounded BER decoder sees input first.
func Canonical(input []byte) ([]byte, error) {
	if len(input) == 0 || len(input) > 16<<20 {
		return nil, errors.New("CMS input exceeds bounds")
	}
	count := 0
	spent := 0
	var item func([]byte, int) ([]byte, int, error)
	item = func(b []byte, depth int) ([]byte, int, error) {
		count++
		if depth > 32 || count > 100000 || len(b) < 2 || b[0]&31 == 31 {
			return nil, 0, errors.New("unsupported CMS BER")
		}
		tag := b[0]
		at := 2
		n := int(b[1])
		indef := n == 128
		if n > 128 {
			sz := n & 127
			if sz > 4 || len(b) < 2+sz {
				return nil, 0, errors.New("invalid CMS length")
			}
			n = 0
			for _, v := range b[2 : 2+sz] {
				n = n<<8 | int(v)
			}
			at += sz
		}
		if indef && tag&32 == 0 {
			return nil, 0, errors.New("indefinite primitive CMS")
		}
		if !indef && (n > len(b)-at || n < 0) {
			return nil, 0, errors.New("truncated CMS")
		}
		end := at + n
		if tag&32 == 0 {
			spent += end
			if spent > 64<<20 {
				return nil, 0, errors.New("CMS decoding budget exceeded")
			}
			return TLV(tag, b[at:end]), end, nil
		}
		var body []byte
		for {
			if indef {
				if at+2 > len(b) {
					return nil, 0, errors.New("unterminated CMS")
				}
				if b[at] == 0 && b[at+1] == 0 {
					at += 2
					break
				}
			} else if at == end {
				break
			} else if at > end {
				return nil, 0, errors.New("CMS child crosses parent")
			}
			limit := b[at:]
			if !indef {
				limit = b[at:end]
			}
			child, used, e := item(limit, depth+1)
			if e != nil {
				return nil, 0, e
			}
			at += used
			if tag == 0x24 {
				var raw asn1.RawValue
				if rest, e := asn1.Unmarshal(child, &raw); e != nil || len(rest) != 0 || raw.Tag != 4 || raw.Class != 0 || raw.IsCompound {
					return nil, 0, errors.New("invalid CMS octet fragments")
				}
				body = append(body, raw.Bytes...)
			} else {
				body = append(body, child...)
			}
		}
		if tag == 0x24 {
			tag = 4
		}
		spent += len(body)
		if spent > 64<<20 {
			return nil, 0, errors.New("CMS decoding budget exceeded")
		}
		return TLV(tag, body), at, nil
	}
	out, used, err := item(input, 0)
	if err != nil {
		return nil, err
	}
	if used != len(input) {
		return nil, errors.New("trailing CMS input")
	}
	return out, nil
}
func TLV(tag byte, body []byte) []byte {
	out := []byte{tag}
	n := len(body)
	if n < 128 {
		out = append(out, byte(n))
	} else {
		var b [8]byte
		i := len(b)
		for n > 0 {
			i--
			b[i] = byte(n)
			n >>= 8
		}
		out = append(out, 128|byte(len(b)-i))
		out = append(out, b[i:]...)
	}
	return append(out, body...)
}

// Verify returns authenticated content, its sole signer, and normalized envelope.
// detached=nil selects attached data; otherwise attached data must be absent.
func Verify(input, detached, expectedCertificate []byte) ([]byte, *x509.Certificate, []byte, error) {
	der, err := Canonical(input)
	if err != nil {
		return nil, nil, nil, err
	}
	p, err := pkcs7.Parse(der)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse CMS: %w", err)
	}
	signer := p.GetOnlySigner()
	if signer == nil {
		return nil, nil, nil, errors.New("exactly one CMS signer required")
	}
	if len(expectedCertificate) > 0 && !bytes.Equal(signer.Raw, expectedCertificate) {
		return nil, nil, nil, errors.New("unexpected CMS signing certificate")
	}
	if detached != nil {
		if len(p.Content) != 0 {
			return nil, nil, nil, errors.New("detached CMS contains attached content")
		}
		p.Content = detached
	}
	seen := map[string]bool{}
	for _, a := range p.Signers[0].AuthenticatedAttributes {
		id := a.Type.String()
		if seen[id] {
			return nil, nil, nil, errors.New("duplicate CMS signed attribute")
		}
		seen[id] = true
	}
	if !seen[pkcs7.OIDAttributeContentType.String()] || !seen[pkcs7.OIDAttributeMessageDigest.String()] {
		return nil, nil, nil, errors.New("CMS signed attributes required")
	}
	var contentType asn1.ObjectIdentifier
	if err = p.UnmarshalSignedAttribute(pkcs7.OIDAttributeContentType, &contentType); err != nil || !contentType.Equal(pkcs7.OIDData) {
		return nil, nil, nil, errors.New("unsupported CMS content type")
	}
	if err = p.Verify(); err != nil {
		return nil, nil, nil, fmt.Errorf("verify CMS: %w", err)
	}
	return p.Content, signer, der, nil
}
