package platform

import (
	"encoding/binary"
	"testing"
)

func universalFixture(order binary.ByteOrder, wide bool) []byte {
	first, second := make([]byte, 256), make([]byte, 256)
	copy(first, thin())
	copy(second, thin())
	binary.LittleEndian.PutUint32(second[8:], 2)
	b := make([]byte, 512+len(second))
	magic, stride := uint32(0xcafebabe), 20
	if wide {
		magic, stride = 0xcafebabf, 32
	}
	order.PutUint32(b, magic)
	order.PutUint32(b[4:], 2)
	for i, data := range [][]byte{first, second} {
		a := b[8+i*stride:]
		order.PutUint32(a, 0x100000c)
		order.PutUint32(a[4:], uint32(i*2))
		offset := uint64(256 + i*256)
		if wide {
			order.PutUint64(a[8:], offset)
			order.PutUint64(a[16:], uint64(len(data)))
			order.PutUint32(a[24:], 8)
		} else {
			order.PutUint32(a[8:], uint32(offset))
			order.PutUint32(a[12:], uint32(len(data)))
			order.PutUint32(a[16:], 8)
		}
		copy(b[offset:], data)
	}
	return b
}

func TestUniversalEndianAndTableWidths(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.BigEndian, binary.LittleEndian} {
		for _, wide := range []bool{false, true} {
			if err := validateMachO(universalFixture(order, wide)); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestUniversalRejectsUnsafeSlices(t *testing.T) {
	for _, kind := range []string{"empty", "too many", "truncated table", "inside table", "overlap", "overflow", "alignment", "mismatch", "duplicate", "simulator", "encrypted", "wrong subtype", "reserved"} {
		t.Run(kind, func(t *testing.T) {
			b := universalFixture(binary.BigEndian, false)
			switch kind {
			case "empty":
				binary.BigEndian.PutUint32(b[4:], 0)
			case "too many":
				binary.BigEndian.PutUint32(b[4:], 65)
			case "truncated table":
				b = b[:30]
			case "inside table":
				binary.BigEndian.PutUint32(b[16:], 16)
			case "overlap":
				binary.BigEndian.PutUint32(b[20:], 300)
			case "overflow":
				binary.BigEndian.PutUint32(b[36:], 0xfffffff0)
			case "alignment":
				binary.BigEndian.PutUint32(b[24:], 31)
			case "mismatch":
				binary.BigEndian.PutUint32(b[32:], 1)
			case "duplicate":
				binary.BigEndian.PutUint32(b[32:], 0)
				binary.LittleEndian.PutUint32(b[520:], 0)
			case "simulator":
				binary.LittleEndian.PutUint32(b[552:], 7)
			case "encrypted":
				binary.LittleEndian.PutUint32(b[544:], 0x2c)
				binary.LittleEndian.PutUint32(b[560:], 1)
			case "wrong subtype":
				binary.BigEndian.PutUint32(b[32:], 1)
				binary.LittleEndian.PutUint32(b[520:], 1)
			case "reserved":
				b = universalFixture(binary.BigEndian, true)
				binary.BigEndian.PutUint32(b[36:], 1)
			}
			if err := validateMachO(b); err == nil {
				t.Fatal("unsafe universal input accepted")
			}
		})
	}
}

func TestUniversalRequiresEqualEntitlements(t *testing.T) {
	makeInput := func(second string) []byte {
		b := universalFixture(binary.BigEndian, false)
		for i, value := range []string{"true", second} {
			start := 256 + i*256
			sig := super([]uint32{5}, [][]byte{blob(0xfade7171, []byte("<plist><dict><key>get-task-allow</key><"+value+"/></dict></plist>"))})
			binary.LittleEndian.PutUint32(b[start+16:], 2)
			binary.LittleEndian.PutUint32(b[start+20:], 40)
			binary.LittleEndian.PutUint32(b[start+56:], 0x1d)
			binary.LittleEndian.PutUint32(b[start+60:], 16)
			binary.LittleEndian.PutUint32(b[start+64:], 96)
			binary.LittleEndian.PutUint32(b[start+68:], uint32(len(sig)))
			copy(b[start+96:], sig)
		}
		return b
	}
	if err := validateMachO(makeInput("true")); err != nil {
		t.Fatal(err)
	}
	if err := validateMachO(makeInput("false")); err == nil {
		t.Fatal("different authorization across slices accepted")
	}
}
