package platform

import (
	"encoding/binary"
	"reflect"
	"sort"
)

type machSlice struct {
	Data   []byte
	Offset uint64
}

// Parse every slice and validate the complete architecture table. Executable
// policy checks every slice; library preparation may explicitly discard obsolete
// 32-bit ARM code before validating and signing the remaining arm64 code.
func machSlices(b []byte) ([]machSlice, error) {
	if len(b) < 4 {
		return nil, failure("Truncated Mach-O header")
	}
	magic := binary.BigEndian.Uint32(b)
	var order binary.ByteOrder = binary.BigEndian
	wide := false
	switch magic {
	case 0xcafebabe:
	case 0xbebafeca:
		order = binary.LittleEndian
	case 0xcafebabf:
		wide = true
	case 0xbfbafeca:
		order = binary.LittleEndian
		wide = true
	default:
		return []machSlice{{Data: b}}, nil
	}
	if len(b) < 8 {
		return nil, failure("Truncated universal architecture table")
	}
	count := uint64(order.Uint32(b[4:]))
	stride := uint64(20)
	if wide {
		stride = 32
	}
	if count == 0 || count > 64 || count > uint64(len(b)-8)/stride {
		return nil, failure("Invalid universal architecture table")
	}
	end := 8 + count*stride
	slices := make([]machSlice, 0, count)
	seen := map[uint64]bool{}
	for i := uint64(0); i < count; i++ {
		a := b[8+i*stride : 8+(i+1)*stride]
		cpu, subtype := order.Uint32(a), order.Uint32(a[4:])
		offset, size, align := uint64(order.Uint32(a[8:])), uint64(order.Uint32(a[12:])), order.Uint32(a[16:])
		if wide {
			offset, size, align = order.Uint64(a[8:]), order.Uint64(a[16:]), order.Uint32(a[24:])
			if order.Uint32(a[28:]) != 0 {
				return nil, failure("Invalid universal reserved field")
			}
		}
		if align > 31 || offset < end || offset > uint64(len(b)) || size < 32 || size > uint64(len(b))-offset || offset%(uint64(1)<<align) != 0 {
			return nil, failure("Invalid universal slice bounds or alignment")
		}
		data := b[offset : offset+size]
		magic := binary.LittleEndian.Uint32(data)
		if (magic != 0xfeedfacf && !(magic == 0xfeedface && cpu == 12)) || binary.LittleEndian.Uint32(data[4:]) != cpu || binary.LittleEndian.Uint32(data[8:]) != subtype {
			return nil, failure("Universal architecture table disagrees with its slice")
		}
		key := uint64(cpu)<<32 | uint64(subtype)
		if seen[key] {
			return nil, failure("Duplicate universal architecture")
		}
		seen[key] = true
		slices = append(slices, machSlice{Data: data, Offset: offset})
	}
	ordered := append([]machSlice(nil), slices...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Offset < ordered[j].Offset })
	for i := 1; i < len(ordered); i++ {
		previous := ordered[i-1]
		if previous.Offset+uint64(len(previous.Data)) > ordered[i].Offset {
			return nil, failure("Overlapping universal slices")
		}
	}
	return slices, nil
}

func consistentSliceEntitlements(slices []machSlice) (map[string]any, error) {
	var first map[string]any
	for i, s := range slices {
		ent, err := thinEntitlements(s.Data)
		if err != nil {
			return nil, err
		}
		// An unsigned slice and an explicitly empty entitlement dictionary are
		// equivalent. Any actual capability/identity discrepancy fails closed.
		if len(ent) == 0 {
			ent = nil
		}
		if i == 0 {
			first = ent
		} else if !reflect.DeepEqual(first, ent) {
			return nil, failure("Universal slices have different entitlements")
		}
	}
	return first, nil
}
