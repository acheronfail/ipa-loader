// Package gosign writes the supported iOS Mach-O signing format using Go crypto.
package gosign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/smallstep/pkcs7"
	"howett.net/plist"
	"ipa-loader/app/internal/cms"
)

type Identity struct {
	Key         *rsa.PrivateKey
	Certificate *x509.Certificate
	Chain       []*x509.Certificate
}
type Options struct {
	Identifier   string
	Entitlements []byte
}

var be = binary.BigEndian
var le = binary.LittleEndian

func words(w ...uint32) []byte {
	out := make([]byte, 4*len(w))
	for i, v := range w {
		be.PutUint32(out[4*i:], v)
	}
	return out
}
func blob(magic uint32, data []byte) []byte {
	return append(words(magic, uint32(8+len(data))), data...)
}
func align(n, a int) int { return (n + a - 1) & ^(a - 1) }
func digest(typ byte, b []byte) []byte {
	if typ == 1 {
		h := sha1.Sum(b)
		return h[:]
	}
	h := sha256.Sum256(b)
	return h[:]
}
func padded(s []byte) []byte {
	return append(append(words(uint32(len(s))), s...), make([]byte, align(len(s), 4)-len(s))...)
}
func requirements(id, cn string) []byte {
	// identifier AND Apple generic anchor AND leaf CN AND WWDR marker exists.
	e := words(1, 6, 2)
	e = append(e, padded([]byte(id))...)
	e = append(e, words(6, 15, 6, 11, 0)...)
	e = append(e, padded([]byte("subject.CN"))...)
	e = append(e, words(1)...)
	e = append(e, padded([]byte(cn))...)
	e = append(e, words(14, 1)...)
	e = append(e, padded([]byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 6, 2, 1})...)
	e = append(e, words(0)...)
	inner := blob(0xfade0c00, e)
	return blob(0xfade0c01, append(words(1, 3, 20), inner...))
}
func derValue(v any, depth int) ([]byte, error) {
	if depth > 32 {
		return nil, errors.New("entitlement nesting exceeds limit")
	}
	switch v := v.(type) {
	case string:
		return asn1.MarshalWithParams(v, "utf8")
	case bool:
		return asn1.Marshal(v)
	case uint64:
		if v > 1<<63-1 {
			return nil, errors.New("entitlement integer too large")
		}
		return asn1.Marshal(int64(v))
	case int64:
		return asn1.Marshal(v)
	case []any:
		var b []byte
		for _, x := range v {
			d, e := derValue(x, depth+1)
			if e != nil {
				return nil, e
			}
			b = append(b, d...)
		}
		return cms.TLV(0x30, b), nil
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b []byte
		for _, k := range keys {
			key, _ := asn1.MarshalWithParams(k, "utf8")
			value, e := derValue(v[k], depth+1)
			if e != nil {
				return nil, e
			}
			b = append(b, cms.TLV(0x30, append(key, value...))...)
		}
		return cms.TLV(0xb0, b), nil
	}
	return nil, fmt.Errorf("unsupported entitlement type %T", v)
}
func directory(code []byte, typ byte, id, team string, special map[int][]byte, execLimit, execFlags uint64) []byte {
	n := 0
	for k := range special {
		if k > n && len(special[k]) > 0 {
			n = k
		}
	}
	size := len(digest(typ, nil))
	pages := (len(code) + 4095) / 4096
	hashAt := 88 + len(id) + 1 + len(team) + 1 + n*size
	b := make([]byte, hashAt+pages*size)
	copy(b, words(0xfade0c02, uint32(len(b)), 0x20400, 0, uint32(hashAt), 88, uint32(n), uint32(pages), uint32(len(code))))
	b[36], b[37], b[39] = byte(size), typ, 12
	be.PutUint32(b[48:], uint32(88+len(id)+1))
	be.PutUint64(b[72:], execLimit)
	be.PutUint64(b[80:], execFlags)
	copy(b[88:], id)
	copy(b[88+len(id)+1:], team)
	for slot, data := range special {
		if len(data) > 0 {
			copy(b[hashAt-slot*size:], digest(typ, data))
		}
	}
	for i := 0; i < pages; i++ {
		end := (i + 1) * 4096
		if end > len(code) {
			end = len(code)
		}
		copy(b[hashAt+i*size:], digest(typ, code[i*4096:end]))
	}
	return b
}
func signature(code []byte, id Identity, opt Options, info, resources []byte, execLimit uint64, fileType uint32) ([]byte, error) {
	if len(id.Chain) == 0 {
		var err error
		id.Chain, err = issuerChain(id.Certificate)
		if err != nil {
			return nil, err
		}
	}

	team := ""
	for _, s := range id.Certificate.Subject.OrganizationalUnit {
		if len(s) == 10 {
			if team != "" && team != s {
				return nil, errors.New("ambiguous certificate team")
			}
			team = s
		}
	}
	if team == "" {
		return nil, errors.New("signing certificate has no team")
	}
	req := requirements(opt.Identifier, id.Certificate.Subject.CommonName)
	slots := map[uint32][]byte{2: req}
	special := map[int][]byte{1: info, 2: req, 3: resources}
	flags := uint64(0)
	if fileType == 2 {
		flags = 1
	}
	if len(opt.Entitlements) > 0 {
		if fileType != 2 {
			return nil, errors.New("entitlements on library unsupported")
		}
		var ent map[string]any
		if _, e := plist.Unmarshal(opt.Entitlements, &ent); e != nil {
			return nil, e
		}
		d, e := derValue(ent, 0)
		if e != nil {
			return nil, e
		}
		slots[5] = blob(0xfade7171, opt.Entitlements)
		slots[7] = blob(0xfade7172, cms.TLV(0x70, append([]byte{2, 1, 1}, d...)))
		special[5] = slots[5]
		special[7] = slots[7]
		if allowed, _ := ent["get-task-allow"].(bool); allowed {
			flags |= 0x10
		}
	}
	// Match the current reference signer's SHA256-only CodeDirectory policy.
	slots[0] = directory(code, 2, opt.Identifier, team, special, execLimit, flags)
	hashes := [][]byte{digest(2, slots[0])[:20]}
	hashPlist, e := plist.Marshal(map[string]any{"cdhashes": hashes}, plist.XMLFormat)
	if e != nil {
		return nil, e
	}
	sd, e := pkcs7.NewSignedData(slots[0])
	if e != nil {
		return nil, e
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	attrs := []pkcs7.Attribute{
		{Type: asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 1}, Value: hashPlist},
		{Type: asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 2}, Value: struct {
			Algorithm asn1.ObjectIdentifier
			Digest    []byte
		}{pkcs7.OIDDigestAlgorithmSHA256, digest(2, slots[0])}},
	}

	if e = sd.AddSignerChain(id.Certificate, id.Key, id.Chain, pkcs7.SignerInfoConfig{ExtraSignedAttributes: attrs}); e != nil {
		return nil, e
	}
	sd.Detach()
	signed, e := sd.Finish()
	if e != nil {
		return nil, e
	}
	slots[0x10000] = blob(0xfade0b01, signed)
	keys := []uint32{0, 2, 5, 7, 0x1000, 0x10000}
	count := 0
	for _, k := range keys {
		if len(slots[k]) > 0 {
			count++
		}
	}
	head := words(0xfade0cc0, 0, uint32(count))
	offset := 12 + count*8
	var body []byte
	for _, k := range keys {
		if v := slots[k]; len(v) > 0 {
			head = append(head, words(k, uint32(offset))...)
			body = append(body, v...)
			offset += len(v)
		}
	}
	out := append(head, body...)
	be.PutUint32(out[4:], uint32(len(out)))
	return out, nil
}

func thin(input []byte, id Identity, opt Options, info, resources []byte) ([]byte, error) {
	if len(input) < 32 || le.Uint32(input) != 0xfeedfacf {
		return nil, errors.New("only little-endian 64-bit Mach-O supported")
	}
	cpu := le.Uint32(input[4:])
	if cpu != 0x100000c {
		return nil, errors.New("only arm64 Mach-O supported")
	}
	fileType := le.Uint32(input[12:])
	if fileType != 2 && fileType != 6 {
		return nil, errors.New("unsupported Mach-O type")
	}
	count, size := int(le.Uint32(input[16:])), int(le.Uint32(input[20:]))
	if count > 10000 || size > len(input)-32 {
		return nil, errors.New("invalid load commands")
	}
	cs, link, textLimit := -1, -1, uint64(0)
	firstData := len(input)
	at := 32
	for i := 0; i < count; i++ {
		if at+8 > 32+size {
			return nil, errors.New("truncated load command")
		}
		cmd, n := le.Uint32(input[at:]), int(le.Uint32(input[at+4:]))
		if n < 8 || at+n > 32+size {
			return nil, errors.New("invalid load command")
		}
		if cmd == 0x1d {
			if cs >= 0 || n != 16 {
				return nil, errors.New("invalid signature command")
			}
			cs = at
		}
		if cmd == 0x21 || cmd == 0x2c {
			if n < 20 || le.Uint32(input[at+16:]) != 0 {
				return nil, errors.New("encrypted binaries unsupported")
			}
		}
		if cmd == 0x19 {
			if n < 72 {
				return nil, errors.New("truncated segment")
			}
			name := string(bytes.TrimRight(input[at+8:at+24], "\x00"))
			if name == "__LINKEDIT" {
				if link >= 0 {
					return nil, errors.New("duplicate linkedit")
				}
				link = at
			}
			if name == "__TEXT" {
				textLimit = le.Uint64(input[at+32:])
			}
			sections := int(le.Uint32(input[at+64:]))
			if n != 72+80*sections {
				return nil, errors.New("invalid sections")
			}
			for j := 0; j < sections; j++ {
				off := int(le.Uint32(input[at+72+80*j+48:]))
				if off > 0 && off < firstData {
					firstData = off
				}
			}
		}
		at += n
	}
	if at != 32+size || link < 0 {
		return nil, errors.New("missing linkedit or invalid commands")
	}
	codeLimit := len(input)
	if cs >= 0 {
		codeLimit = int(le.Uint32(input[cs+8:]))
		allocated := int(le.Uint32(input[cs+12:]))
		if codeLimit < 32+size || codeLimit > len(input) || allocated > len(input)-codeLimit || len(bytes.Trim(input[codeLimit+allocated:], "\x00")) != 0 {
			return nil, errors.New("signature must be final Mach-O data")
		}
	}
	if cs < 0 {
		if 32+size+16 > firstData || 32+size+16 > len(input) || !bytes.Equal(input[32+size:32+size+16], make([]byte, 16)) {
			return nil, errors.New("no room for signature command")
		}
		cs = 32 + size
		count++
		size += 16
	}
	codeLimit = align(codeLimit, 16)
	code := make([]byte, codeLimit)
	copy(code, input[:min(codeLimit, len(input))])
	copy(code[cs:], []byte{0x1d, 0, 0, 0, 16, 0, 0, 0})
	le.PutUint32(code[16:], uint32(count))
	le.PutUint32(code[20:], uint32(size))
	le.PutUint32(code[cs+8:], uint32(codeLimit))
	// Fixed allocation avoids a circular dependency between page hashes and the
	// load command's signature length. Bounds include large entitlement/cert data.
	allocation := align(32768+(codeLimit+4095)/4096*52+len(opt.Entitlements)*4, 16)
	le.PutUint32(code[cs+12:], uint32(allocation))
	off := le.Uint64(code[link+40:])
	if off > uint64(codeLimit) {
		return nil, errors.New("invalid linkedit offset")
	}
	end := uint64(codeLimit+allocation) - off
	le.PutUint64(code[link+48:], end)
	le.PutUint64(code[link+32:], uint64(align(int(end), 16384)))
	sig, e := signature(code, id, opt, info, resources, textLimit, fileType)
	if e != nil {
		return nil, e
	}
	if len(sig) > allocation {
		return nil, errors.New("signature allocation exceeded")
	}
	out := append(code, make([]byte, allocation)...)
	copy(out[codeLimit:], sig)
	return out, nil
}
func binaryImage(input []byte, id Identity, opt Options, info, resources []byte) ([]byte, error) {
	if len(input) < 8 {
		return nil, errors.New("truncated Mach-O")
	}
	magic := be.Uint32(input)
	if magic != 0xcafebabe && magic != 0xbebafeca && magic != 0xcafebabf && magic != 0xbfbafeca {
		return thin(input, id, opt, info, resources)
	}
	var order binary.ByteOrder = be
	if magic == 0xbebafeca || magic == 0xbfbafeca {
		order = le
	}
	step := 20
	wide := magic == 0xcafebabf || magic == 0xbfbafeca
	if wide {
		step = 32
	}
	n := int(order.Uint32(input[4:]))
	if n < 1 || n > 64 || 8+step*n > len(input) {
		return nil, errors.New("invalid universal table")
	}
	out := append([]byte{}, input[:8+step*n]...)
	seen := map[uint64]bool{}
	spans := [][2]uint64{}
	for i := 0; i < n; i++ {
		at := 8 + step*i
		cpu, sub := order.Uint32(input[at:]), order.Uint32(input[at+4:])
		key := uint64(cpu)<<32 | uint64(sub)
		if seen[key] {
			return nil, errors.New("duplicate architecture")
		}
		seen[key] = true
		offset, size, alignment := uint64(order.Uint32(input[at+8:])), uint64(order.Uint32(input[at+12:])), order.Uint32(input[at+16:])
		if wide {
			offset = order.Uint64(input[at+8:])
			size = order.Uint64(input[at+16:])
			alignment = order.Uint32(input[at+24:])
			if order.Uint32(input[at+28:]) != 0 {
				return nil, errors.New("invalid universal reserved field")
			}
		}
		if alignment > 20 || offset%(1<<alignment) != 0 || offset < uint64(8+step*n) || offset > uint64(len(input)) || size > uint64(len(input))-offset {
			return nil, errors.New("invalid universal slice")
		}
		for _, s := range spans {
			if offset < s[1] && s[0] < offset+size {
				return nil, errors.New("overlapping universal slices")
			}
		}
		spans = append(spans, [2]uint64{offset, offset + size})
		part := input[offset : offset+size]
		if len(part) < 12 || le.Uint32(part[4:]) != cpu || le.Uint32(part[8:]) != sub {
			return nil, errors.New("architecture descriptor mismatch")
		}
		signed, e := thin(part, id, opt, info, resources)
		if e != nil {
			return nil, e
		}
		next := align(len(out), 1<<alignment)
		out = append(out, make([]byte, next-len(out))...)
		if wide {
			order.PutUint64(out[at+8:], uint64(next))
			order.PutUint64(out[at+16:], uint64(len(signed)))
		} else {
			order.PutUint32(out[at+8:], uint32(next))
			order.PutUint32(out[at+12:], uint32(len(signed)))
		}
		out = append(out, signed...)
	}
	return out, nil
}

// Sign signs exactly one code object. Children are already signed and remain
// unchanged; their bytes are sealed into the parent's resource manifest.
func Sign(ctx context.Context, path string, id Identity, opt Options) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if id.Key == nil || id.Certificate == nil || opt.Identifier == "" || strings.ContainsAny(opt.Identifier, "\x00\r\n") {
		return errors.New("invalid signing identity")
	}
	pub, ok := id.Certificate.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.Cmp(id.Key.N) != 0 || pub.E != id.Key.E {
		return errors.New("certificate/key mismatch")
	}
	executable := path
	var info, resources []byte
	s, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if s.Mode()&os.ModeSymlink != 0 {
		return errors.New("linked signing input")
	}
	if s.IsDir() {
		info, err = os.ReadFile(filepath.Join(path, "Info.plist"))
		if err != nil {
			return err
		}
		var metadata map[string]any
		if _, err = plist.Unmarshal(info, &metadata); err != nil {
			return err
		}
		name, _ := metadata["CFBundleExecutable"].(string)
		if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, "/\\:") {
			return errors.New("unsafe bundle executable")
		}
		if metadata["CFBundleIdentifier"] != opt.Identifier {
			return errors.New("bundle identifier mismatch")
		}
		executable = filepath.Join(path, name)
		files := map[string]any{}
		files2 := map[string]any{}
		err = filepath.WalkDir(path, func(p string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if e = ctx.Err(); e != nil {
				return e
			}
			if d.Type()&os.ModeSymlink != 0 {
				return errors.New("linked resource")
			}
			if d.IsDir() {
				return nil
			}
			if !d.Type().IsRegular() {
				return errors.New("nonregular resource")
			}
			rel, e := filepath.Rel(path, p)
			if e != nil {
				return e
			}
			rel = filepath.ToSlash(rel)
			if p == executable || rel == "_CodeSignature/CodeResources" {
				return nil
			}
			data, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			files[rel] = digest(1, data)
			if rel != "Info.plist" {
				files2[rel] = map[string]any{"hash": digest(1, data), "hash2": digest(2, data)}
			}
			return nil
		})
		if err != nil {
			return err
		}
		resources, err = plist.Marshal(map[string]any{"files": files, "files2": files2, "rules": map[string]any{"^.*": true}, "rules2": map[string]any{"^.*": true, "^Info\\.plist$": map[string]any{"omit": true, "weight": 10.0}}}, plist.XMLFormat)
		if err != nil {
			return err
		}
		if err = os.MkdirAll(filepath.Join(path, "_CodeSignature"), 0700); err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(path, "_CodeSignature/CodeResources"), resources, 0600); err != nil {
			return err
		}
	} else if !s.Mode().IsRegular() {
		return errors.New("nonregular signing input")
	}
	stat, err := os.Lstat(executable)
	if err != nil {
		return err
	}
	if !stat.Mode().IsRegular() || stat.Size() > 512<<20 {
		return errors.New("invalid signing input size or type")
	}
	data, err := os.ReadFile(executable)
	if err != nil {
		return err
	}
	if len(data) > 512<<20 {
		return errors.New("signing input too large")
	}
	signed, err := binaryImage(data, id, opt, info, resources)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return os.WriteFile(executable, signed, 0755)
}

var _ crypto.Signer = (*rsa.PrivateKey)(nil)
