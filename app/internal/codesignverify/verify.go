// Package codesignverify independently checks the supported iOS signing format.
// CMS integrity is checked without certificate-chain trust; iOS remains the
// authority for profile authorization and device installation policy.
package codesignverify

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type Options struct {
	AllowAdHoc            bool
	CertificateDER        []byte
	Identifier            string
	Entitlements          []byte
	RequireNoEntitlements bool
}
type Report struct {
	Images         []Image
	ResourceHashes int
}
type Image struct {
	Path        string
	Slices      int
	CDHashes    [][]byte
	CMSVerified bool
}
type verifier struct {
	ctx     context.Context
	options Options
	report  Report
	images  map[string]Image
	root    string
}

type contextReader struct {
	ctx   context.Context
	input io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.input.Read(p)
}

func VerifyBundle(ctx context.Context, bundlePath string, options Options) (Report, error) {
	root, err := filepath.Abs(bundlePath)
	if err != nil {
		return Report{}, err
	}
	v := &verifier{ctx: ctx, options: options, images: map[string]Image{}, root: root}
	if err = v.bundle(root); err != nil {
		return Report{}, err
	}
	return v.report, nil
}

func VerifyBinary(ctx context.Context, filename string, options Options) (Report, error) {
	root, err := filepath.Abs(filename)
	if err != nil {
		return Report{}, err
	}
	v := &verifier{ctx: ctx, options: options, images: map[string]Image{}, root: root}
	if err = v.image(root, nil, nil, options.Identifier); err != nil {
		return Report{}, err
	}
	return v.report, nil
}

func invalid(message string) error { return errors.New("Code signature verification: " + message) }
func u32(b []byte, at int) uint32  { return binary.BigEndian.Uint32(b[at : at+4]) }
func region(b []byte, offset, size uint64) ([]byte, error) {
	if offset > uint64(len(b)) || size > uint64(len(b))-offset {
		return nil, invalid("out-of-bounds signature data")
	}
	return b[offset : offset+size], nil
}
func boundedFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, invalid("missing, linked or oversized input")
	}
	return os.ReadFile(path)
}
func slices(b []byte) ([][]byte, error) {
	if len(b) < 8 {
		return nil, invalid("truncated Mach-O")
	}
	magic := u32(b, 0)
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
		return [][]byte{b}, nil
	}
	n := uint64(order.Uint32(b[4:8]))
	stride := uint64(20)
	if wide {
		stride = 32
	}
	if n == 0 || n > 64 || n*stride > uint64(len(b)-8) {
		return nil, invalid("invalid universal table")
	}
	type span struct{ start, end uint64 }
	seen := []span{}
	architectures := map[uint64]bool{}
	result := [][]byte{}
	for i := uint64(0); i < n; i++ {
		e := b[8+i*stride : 8+(i+1)*stride]
		offset, size := uint64(order.Uint32(e[8:12])), uint64(order.Uint32(e[12:16]))
		align := order.Uint32(e[16:20])
		if wide {
			offset = order.Uint64(e[8:16])
			size = order.Uint64(e[16:24])
			align = order.Uint32(e[24:28])
			if order.Uint32(e[28:32]) != 0 {
				return nil, invalid("unsupported universal reserved field")
			}
		}
		if offset < 8+n*stride || size < 32 || align > 31 || offset%(uint64(1)<<align) != 0 {
			return nil, invalid("invalid universal slice")
		}
		part, err := region(b, offset, size)
		if err != nil {
			return nil, err
		}
		cpu, subtype := order.Uint32(e[:4]), order.Uint32(e[4:8])
		key := uint64(cpu)<<32 | uint64(subtype)
		if architectures[key] || binary.LittleEndian.Uint32(part[:4]) != 0xfeedfacf || binary.LittleEndian.Uint32(part[4:8]) != cpu || binary.LittleEndian.Uint32(part[8:12]) != subtype {
			return nil, invalid("universal architecture descriptor mismatch")
		}
		architectures[key] = true
		for _, p := range seen {
			if offset < p.end && p.start < offset+size {
				return nil, invalid("overlapping universal slices")
			}
		}
		seen = append(seen, span{offset, offset + size})
		result = append(result, part)
	}
	return result, nil
}
func signature(b []byte) (map[uint32][]byte, int, error) {
	if len(b) < 32 || binary.LittleEndian.Uint32(b[:4]) != 0xfeedfacf {
		return nil, 0, invalid("only 64-bit little-endian Mach-O is supported")
	}
	n, size := uint64(binary.LittleEndian.Uint32(b[16:20])), uint64(binary.LittleEndian.Uint32(b[20:24]))
	if n > 4096 || size > uint64(len(b)-32) {
		return nil, 0, invalid("invalid load commands")
	}
	at, end := uint64(32), uint64(32)+size
	offset, length := uint64(0), uint64(0)
	for i := uint64(0); i < n; i++ {
		if at+8 > end {
			return nil, 0, invalid("truncated load command")
		}
		cmd, sz := binary.LittleEndian.Uint32(b[at:at+4]), uint64(binary.LittleEndian.Uint32(b[at+4:at+8]))
		if sz < 8 || sz%8 != 0 || sz > end-at {
			return nil, 0, invalid("invalid load-command size")
		}
		if cmd == 0x1d {
			if length != 0 || sz != 16 {
				return nil, 0, invalid("duplicate or invalid code-signature command")
			}
			offset = uint64(binary.LittleEndian.Uint32(b[at+8 : at+12]))
			length = uint64(binary.LittleEndian.Uint32(b[at+12 : at+16]))
		}
		at += sz
	}
	if at != end || length < 12 || offset < end || offset+length != uint64(len(b)) {
		return nil, 0, invalid("missing or unsupported signature allocation")
	}
	sig, err := region(b, offset, length)
	if err != nil {
		return nil, 0, err
	}
	if u32(sig, 0) != 0xfade0cc0 {
		return nil, 0, invalid("unsupported signature superblob")
	}
	used, count := uint64(u32(sig, 4)), uint64(u32(sig, 8))
	if used > length || used < 12 || count > 32 || 12+count*8 > used {
		return nil, 0, invalid("invalid signature index")
	}
	for _, value := range sig[used:] {
		if value != 0 {
			return nil, 0, invalid("nonzero signature allocation padding")
		}
	}
	blobs := map[uint32][]byte{}
	spans := [][2]uint64{}
	for i := uint64(0); i < count; i++ {
		typ, off := u32(sig, int(12+i*8)), uint64(u32(sig, int(16+i*8)))
		if off < 12+count*8 || off+8 > used {
			return nil, 0, invalid("invalid signature child offset")
		}
		sz := uint64(u32(sig, int(off+4)))
		if sz < 8 || sz > used-off {
			return nil, 0, invalid("invalid signature child size")
		}
		if _, ok := blobs[typ]; ok {
			return nil, 0, invalid("duplicate signature slot")
		}
		for _, p := range spans {
			if off < p[1] && p[0] < off+sz {
				return nil, 0, invalid("overlapping signature children")
			}
		}
		spans = append(spans, [2]uint64{off, off + sz})
		blobs[typ] = sig[off : off+sz]
		magic := u32(blobs[typ], 0)
		valid := typ == 0 && magic == 0xfade0c02 || typ >= 0x1000 && typ <= 0x1005 && magic == 0xfade0c02 || typ == 2 && magic == 0xfade0c01 || typ == 5 && magic == 0xfade7171 || typ == 7 && magic == 0xfade7172 || typ == 0x10000 && magic == 0xfade0b01
		if !valid {
			return nil, 0, invalid("unsupported signature slot")
		}
	}
	if blobs[0] == nil {
		return nil, 0, invalid("missing primary CodeDirectory")
	}
	return blobs, int(offset), nil
}
func digest(typ byte, b []byte) ([]byte, error) {
	switch typ {
	case 1:
		h := sha1.Sum(b)
		return h[:], nil
	case 2:
		h := sha256.Sum256(b)
		return h[:], nil
	}
	return nil, invalid("unsupported CodeDirectory digest algorithm")
}
func directory(cd, code []byte, limit int, blobs map[uint32][]byte, info, resources []byte) ([]byte, error) {
	if len(cd) < 44 {
		return nil, invalid("truncated CodeDirectory")
	}
	version := u32(cd, 8)
	minimum := 44
	if version >= 0x20100 {
		minimum = 48
	}
	if version >= 0x20200 {
		minimum = 52
	}
	if version >= 0x20300 {
		minimum = 64
	}
	if version >= 0x20400 {
		minimum = 88
	}
	if version < 0x20001 || version > 0x20400 || len(cd) < minimum {
		return nil, invalid("unsupported CodeDirectory version")
	}
	if version >= 0x20100 && u32(cd, 44) != 0 {
		return nil, invalid("scatter signing unsupported")
	}
	if version >= 0x20300 && binary.BigEndian.Uint64(cd[56:64]) != 0 {
		return nil, invalid("64-bit code limits unsupported")
	}
	hashOffset, identifier, special, pages, codeLimit := uint64(u32(cd, 16)), uint64(u32(cd, 20)), uint64(u32(cd, 24)), uint64(u32(cd, 28)), uint64(u32(cd, 32))
	hashSize, typ, pageExponent := uint64(cd[36]), cd[37], cd[39]
	if typ != 1 && typ != 2 || hashSize != uint64(map[byte]int{1: 20, 2: 32}[typ]) || pageExponent != 12 || special > 7 || codeLimit != uint64(limit) {
		return nil, invalid("unsupported CodeDirectory layout")
	}
	if identifier < uint64(minimum) || identifier >= uint64(len(cd)) || bytes.IndexByte(cd[identifier:], 0) < 0 {
		return nil, invalid("invalid signed identifier")
	}
	if version >= 0x20200 {
		team := uint64(u32(cd, 48))
		if team != 0 && (team < uint64(minimum) || team >= uint64(len(cd)) || bytes.IndexByte(cd[team:], 0) < 0) {
			return nil, invalid("invalid signed team")
		}
	}
	if hashOffset < special*hashSize+uint64(minimum) || hashOffset > uint64(len(cd)) || pages > (uint64(len(cd))-hashOffset)/hashSize || pages != (codeLimit+4095)/4096 {
		return nil, invalid("invalid CodeDirectory hash table")
	}
	for i := uint64(0); i < pages; i++ {
		end := (i + 1) * 4096
		if end > codeLimit {
			end = codeLimit
		}
		hash, _ := digest(typ, code[i*4096:end])
		if !bytes.Equal(hash, cd[hashOffset+i*hashSize:hashOffset+(i+1)*hashSize]) {
			return nil, invalid("code page hash mismatch")
		}
	}
	for slot := uint64(1); slot <= special; slot++ {
		var source []byte
		switch slot {
		case 1:
			source = info
		case 3:
			source = resources
		case 2, 5, 7:
			source = blobs[uint32(slot)]
		}
		expected := cd[hashOffset-slot*hashSize : hashOffset-(slot-1)*hashSize]
		if source == nil {
			if !bytes.Equal(expected, make([]byte, hashSize)) {
				return nil, invalid("missing special-slot input")
			}
		} else {
			hash, _ := digest(typ, source)
			if !bytes.Equal(hash, expected) {
				return nil, invalid(fmt.Sprintf("special-slot %d hash mismatch", slot))
			}
		}
	}
	for _, slot := range []uint32{2, 5, 7} {
		if blobs[slot] != nil && uint64(slot) > special {
			return nil, invalid("unsealed special-slot blob")
		}
	}
	hash, err := digest(typ, cd)
	return hash, err
}
