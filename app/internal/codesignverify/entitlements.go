package codesignverify

import (
	"encoding/asn1"
	"math"
	"reflect"
	"unicode/utf8"

	"howett.net/plist"
)

func checkEntitlements(blobs map[uint32][]byte, expected []byte, root, requireNone bool) error {
	xml, der := blobs[5], blobs[7]
	if xml == nil {
		if der != nil || root && expected != nil {
			return invalid("XML entitlements missing")
		}
		return nil
	}
	var actual map[string]any
	if _, err := plist.Unmarshal(xml[8:], &actual); err != nil || actual == nil {
		return invalid("invalid XML entitlements")
	}
	if root && requireNone && len(actual) != 0 {
		return invalid("library code must not carry app entitlements")
	}
	if der != nil {
		values, err := children(der[8:])
		if err != nil || len(values) != 1 {
			return invalid("invalid DER entitlements")
		}
		envelope := values[0]
		if envelope.Class != 1 || envelope.Tag != 16 || !envelope.IsCompound {
			return invalid("unsupported DER entitlement envelope")
		}
		fields, err := children(envelope.Bytes)
		if err != nil || len(fields) != 2 || fields[0].Class != 0 || fields[0].Tag != 2 || len(fields[0].Bytes) != 1 || fields[0].Bytes[0] != 1 {
			return invalid("unsupported DER entitlement version")
		}
		decoded, err := entitlementValue(fields[1], 0)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(normalize(actual), normalize(decoded)) {
			return invalid("XML and DER entitlements differ")
		}
	} else if root && expected != nil {
		return invalid("DER entitlements required for requested app entitlements")
	}
	if root && expected != nil {
		var want map[string]any
		if _, err := plist.Unmarshal(expected, &want); err != nil || !reflect.DeepEqual(normalize(actual), normalize(want)) {
			return invalid("signed entitlements differ from requested entitlements")
		}
	}
	return nil
}

func normalize(value any) any {
	switch value := value.(type) {
	case uint64:
		if value <= math.MaxInt64 {
			return int64(value)
		}
	case uint:
		if uint64(value) <= math.MaxInt64 {
			return int64(value)
		}
	case int:
		return int64(value)
	case map[string]any:
		result := map[string]any{}
		for key, child := range value {
			result[key] = normalize(child)
		}
		return result
	case []any:
		result := make([]any, len(value))
		for i, child := range value {
			result[i] = normalize(child)
		}
		return result
	}
	return value
}

func entitlementValue(value asn1.RawValue, depth int) (any, error) {
	if depth > 32 {
		return nil, invalid("excessive DER entitlement nesting")
	}
	if value.Class == 0 {
		switch value.Tag {
		case 12:
			if !utf8.Valid(value.Bytes) {
				return nil, invalid("invalid DER UTF-8 entitlement")
			}
			return string(value.Bytes), nil
		case 1:
			if len(value.Bytes) != 1 || value.Bytes[0] != 0 && value.Bytes[0] != 255 {
				return nil, invalid("invalid DER boolean")
			}
			return value.Bytes[0] == 255, nil
		case 2:
			var integer int64
			rest, err := asn1.Unmarshal(value.FullBytes, &integer)
			if err != nil || len(rest) != 0 {
				return nil, invalid("invalid DER integer")
			}
			return integer, nil
		case 16:
			items, err := children(value.Bytes)
			if err != nil {
				return nil, err
			}
			result := []any{}
			for _, item := range items {
				child, err := entitlementValue(item, depth+1)
				if err != nil {
					return nil, err
				}
				result = append(result, child)
			}
			return result, nil
		}
	}
	if value.Class == 2 && value.Tag == 16 && value.IsCompound {
		entries, err := children(value.Bytes)
		if err != nil {
			return nil, err
		}
		result := map[string]any{}
		for _, entry := range entries {
			pair, err := sequence(entry)
			if err != nil || len(pair) != 2 || pair[0].Class != 0 || pair[0].Tag != 12 || !utf8.Valid(pair[0].Bytes) {
				return nil, invalid("invalid DER dictionary entry")
			}
			key := string(pair[0].Bytes)
			if _, exists := result[key]; exists {
				return nil, invalid("duplicate DER entitlement key")
			}
			child, err := entitlementValue(pair[1], depth+1)
			if err != nil {
				return nil, err
			}
			result[key] = child
		}
		return result, nil
	}
	return nil, invalid("unsupported DER entitlement value")
}
