package codesignverify

import (
	"bytes"
	"encoding/asn1"
	"ipa-loader/app/internal/cms"

	"howett.net/plist"
)

func (v *verifier) cms(signature []byte, directories [][]byte) error {
	if err := v.ctx.Err(); err != nil {
		return err
	}
	if len(directories) == 0 {
		return invalid("missing CodeDirectory")
	}
	_, _, normalized, err := cms.Verify(signature, directories[0], v.options.CertificateDER)
	if err != nil {
		return invalid(err.Error())
	}
	return agility(normalized, directories)
}

func children(data []byte) ([]asn1.RawValue, error) {
	values := []asn1.RawValue{}
	for len(data) > 0 {
		var value asn1.RawValue
		rest, err := asn1.Unmarshal(data, &value)
		if err != nil || len(rest) >= len(data) || len(values) >= 256 {
			return nil, invalid("unsupported CMS ASN.1")
		}
		values = append(values, value)
		data = rest
	}
	return values, nil
}
func sequence(value asn1.RawValue) ([]asn1.RawValue, error) {
	if value.Class != 0 || value.Tag != 16 || !value.IsCompound {
		return nil, invalid("expected CMS ASN.1 sequence")
	}
	return children(value.Bytes)
}
func oid(value asn1.RawValue) (string, error) {
	var result asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(value.FullBytes, &result)
	if err != nil || len(rest) != 0 {
		return "", invalid("invalid CMS object identifier")
	}
	return result.String(), nil
}

func agility(data []byte, directories [][]byte) error {
	top, err := children(data)
	if err != nil || len(top) != 1 {
		return invalid("invalid CMS content")
	}
	outer, err := sequence(top[0])
	if err != nil || len(outer) != 2 {
		return invalid("unsupported CMS ContentInfo")
	}
	id, err := oid(outer[0])
	if err != nil || id != "1.2.840.113549.1.7.2" || outer[1].Class != 2 || outer[1].Tag != 0 {
		return invalid("CMS SignedData required")
	}
	wrap, err := children(outer[1].Bytes)
	if err != nil || len(wrap) != 1 {
		return invalid("invalid CMS SignedData wrapper")
	}
	signed, err := sequence(wrap[0])
	if err != nil || len(signed) < 4 {
		return invalid("invalid CMS SignedData fields")
	}
	set := signed[len(signed)-1]
	if set.Class != 0 || set.Tag != 17 {
		return invalid("missing CMS signer set")
	}
	signers, err := children(set.Bytes)
	if err != nil || len(signers) != 1 {
		return invalid("exactly one CMS signer is required")
	}
	fields, err := sequence(signers[0])
	if err != nil || len(fields) < 6 || fields[3].Class != 2 || fields[3].Tag != 0 {
		return invalid("signed CMS attributes required")
	}
	attrs, err := children(fields[3].Bytes)
	if err != nil {
		return err
	}
	found := false
	seen := map[string]bool{}
	for _, attr := range attrs {
		pair, err := sequence(attr)
		if err != nil || len(pair) != 2 {
			return invalid("invalid CMS attribute")
		}
		id, err := oid(pair[0])
		if err != nil || seen[id] {
			return invalid("duplicate or invalid CMS attribute")
		}
		seen[id] = true
		if pair[1].Class != 0 || pair[1].Tag != 17 {
			return invalid("invalid CMS attribute values")
		}
		values, err := children(pair[1].Bytes)
		if err != nil {
			return err
		}
		switch id {
		case "1.2.840.113635.100.9.1":
			if len(values) != 1 || values[0].Tag != 4 || values[0].Class != 0 {
				return invalid("unsupported plist hash agility")
			}
			var dict map[string]any
			if _, err = plist.Unmarshal(values[0].Bytes, &dict); err != nil || len(dict) != 1 {
				return invalid("invalid plist hash agility")
			}
			hashes, ok := dict["cdhashes"].([]any)
			if !ok || len(hashes) != len(directories) {
				return invalid("hash-agility directory count mismatch")
			}
			for i, raw := range hashes {
				hash, ok := raw.([]byte)
				actual, err := digest(directories[i][37], directories[i])
				if !ok || err != nil || !bytes.Equal(hash, actual[:20]) {
					return invalid("signed CodeDirectory hash-agility mismatch")
				}
			}
			found = true
		case "1.2.840.113635.100.9.2":
			if len(values) != len(directories) {
				return invalid("digest hash-agility directory count mismatch")
			}
			matched := map[int]bool{}
			for _, value := range values {
				pair, err := sequence(value)
				if err != nil || len(pair) != 2 || pair[1].Class != 0 || pair[1].Tag != 4 {
					return invalid("unsupported digest hash agility")
				}
				algorithm, err := oid(pair[0])
				if err != nil {
					return err
				}
				match := -1
				for i, cd := range directories {
					want := map[byte]string{1: "1.3.14.3.2.26", 2: "2.16.840.1.101.3.4.2.1"}[cd[37]]
					actual, _ := digest(cd[37], cd)
					if !matched[i] && algorithm == want && bytes.Equal(actual, pair[1].Bytes) {
						match = i
						break
					}
				}
				if match < 0 {
					return invalid("signed CodeDirectory full-digest mismatch")
				}
				matched[match] = true
			}
			found = true
		}
	}
	if len(directories) > 1 && !found {
		return invalid("alternate CodeDirectories lack authenticated hash agility")
	}
	return nil
}
