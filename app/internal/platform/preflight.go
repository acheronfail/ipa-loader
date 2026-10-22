package platform

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
	"howett.net/plist"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"syscall"
	"unicode/utf8"
)

var bundlePattern = regexp.MustCompile(`^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$`)

type appInfo struct {
	Path, Executable, BundleID, Version, Build string
	Embedded                                   []codeObject
	Sharing                                    sharingRequest
	Networking                                 networkRequest
}

func (a *appInfo) applyBundleIdentity(ids bundleIdentity) error {
	bundle := ids.Installed
	if !bundlePattern.MatchString(bundle) || len(bundle) > 255 {
		return failure("Could not prepare an identifier for this account")
	}
	p := filepath.Join(a.Path, "Info.plist")
	b, err := readLimited(p, 1<<20)
	if err != nil {
		return failure("Could not read app metadata")
	}
	m, err := dictionary(b)
	if err != nil {
		return err
	}
	_, hasALT := m["ALTBundleIdentifier"]
	if bundle == ids.Original && a.BundleID == bundle && !hasALT {
		return nil
	}
	m["CFBundleIdentifier"] = bundle
	if bundle == ids.Original {
		delete(m, "ALTBundleIdentifier")
	} else {
		m["ALTBundleIdentifier"] = ids.Original
	}
	b, err = plist.Marshal(m, plist.XMLFormat)
	if err != nil {
		return failure("Could not encode app metadata")
	}
	if err = os.WriteFile(p, b, 0600); err != nil {
		return failure("Could not update app metadata")
	}
	a.BundleID = bundle
	return nil
}

func failure(s string) error { return errors.New(s) }
func dictionary(b []byte) (map[string]any, error) {
	var m map[string]any
	_, e := plist.Unmarshal(b, &m)
	if e != nil || m == nil {
		return nil, failure("Invalid property list")
	}
	return m, nil
}
func stringField(m map[string]any, k string) string { s, _ := m[k].(string); return s }
func validText(s string) bool                       { return s != "" && !strings.ContainsAny(s, "\r\n\x00") }
func zipPlan(files []*zip.File) (string, error) {
	if len(files) > 100000 {
		return "", failure("Too many IPA archive members")
	}
	seen := map[string]bool{}
	regular := map[string]bool{}
	apps := map[string]bool{}
	var total uint64
	for _, f := range files {
		n := strings.TrimSuffix(f.Name, "/")
		parts := strings.Split(n, "/")
		if n == "" || strings.HasPrefix(n, "/") || strings.ContainsAny(n, "\\:\x00\r\n") || !utf8.ValidString(n) {
			return "", failure("Unsafe IPA archive path")
		}
		for _, r := range n {
			if r < 32 {
				return "", failure("Unsafe IPA archive control character")
			}
		}
		for _, p := range parts {
			if p == "" || p == "." || p == ".." {
				return "", failure("Unsafe IPA archive path")
			}
		}
		k := cases.Fold().String(norm.NFC.String(n))
		if seen[k] {
			return "", failure("Duplicate or case-colliding IPA archive path")
		}
		seen[k] = true
		mode := f.Mode()
		if f.Flags&1 != 0 || (!mode.IsRegular() && !mode.IsDir()) {
			return "", failure("Encrypted, linked or special IPA archive members are unsupported")
		}
		if !mode.IsDir() {
			regular[k] = true
		}
		if f.UncompressedSize64 >= math.MaxInt64 || total >= math.MaxInt64-f.UncompressedSize64 {
			return "", failure("IPA expanded size exceeds the supported filesystem range")
		}
		total += f.UncompressedSize64
		if len(parts) >= 2 && parts[0] == "Payload" && strings.HasSuffix(parts[1], ".app") {
			apps[path.Join(parts[:2]...)] = true
		}
	}
	for n := range seen {
		for p := path.Dir(n); p != "."; p = path.Dir(p) {
			if regular[p] {
				return "", failure("IPA archive path traverses a file")
			}
		}
	}
	if len(apps) != 1 {
		return "", failure("Expected one main app in Payload")
	}
	for a := range apps {
		return a, nil
	}
	panic("unreachable")
}
func extractIPA(ctx context.Context, ipa, work string) (appInfo, error) {
	z, e := zip.OpenReader(ipa)
	if e != nil {
		return appInfo{}, failure("Could not open the IPA archive")
	}
	defer z.Close()
	prefix, e := zipPlan(z.File)
	if e != nil {
		return appInfo{}, e
	}
	var expanded uint64
	for _, f := range z.File {
		if strings.HasPrefix(f.Name, prefix+"/") {
			expanded += f.UncompressedSize64
		}
	}
	if e = checkExtractionSpace(work, expanded); e != nil {
		return appInfo{}, e
	}
	for _, f := range z.File {
		if ctx.Err() != nil {
			return appInfo{}, ctx.Err()
		}
		if f.Name != prefix+"/" && !strings.HasPrefix(f.Name, prefix+"/") {
			continue
		}
		dest := filepath.Join(work, filepath.FromSlash(f.Name))
		if f.FileInfo().IsDir() {
			if e = os.MkdirAll(dest, 0700); e != nil {
				return appInfo{}, failure("Could not extract IPA")
			}
			continue
		}
		if e = os.MkdirAll(filepath.Dir(dest), 0700); e != nil {
			return appInfo{}, failure("Could not extract IPA")
		}
		in, e := f.Open()
		if e != nil {
			return appInfo{}, failure("Could not read IPA member")
		}
		out, e := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			in.Close()
			return appInfo{}, failure("Could not extract IPA")
		}
		count, copyErr := io.Copy(out, io.LimitReader(contextReader{ctx, in}, int64(f.UncompressedSize64)+1))
		closeErr := out.Close()
		in.Close()
		if errors.Is(copyErr, syscall.ENOSPC) || errors.Is(closeErr, syscall.ENOSPC) {
			return appInfo{}, failure("Not enough free disk space to unpack this IPA")
		}
		if copyErr != nil || closeErr != nil || count != int64(f.UncompressedSize64) {
			return appInfo{}, failure("IPA member integrity check failed")
		}
	}
	a := appInfo{Path: filepath.Join(work, filepath.FromSlash(prefix))}
	b, e := readLimited(filepath.Join(a.Path, "Info.plist"), 1<<20)
	if e != nil {
		return a, failure("App Info.plist is missing")
	}
	m, e := dictionary(b)
	if e != nil {
		return a, e
	}
	a.Executable = stringField(m, "CFBundleExecutable")
	a.BundleID = stringField(m, "CFBundleIdentifier")
	a.Version = stringField(m, "CFBundleShortVersionString")
	a.Build = stringField(m, "CFBundleVersion")
	if !validText(a.Executable) || filepath.Base(a.Executable) != a.Executable || strings.ContainsAny(a.Executable, "/\\:") || !bundlePattern.MatchString(a.BundleID) || !validText(a.Version) || !validText(a.Build) {
		return a, failure("Unsupported app bundle metadata")
	}
	a.Embedded, e = inspectCode(ctx, a)
	if e != nil {
		return a, e
	}
	a.Networking, e = readNetworkRequest(filepath.Join(a.Path, a.Executable))
	if e != nil {
		return a, e
	}
	a.Sharing, e = readSharingRequest(filepath.Join(a.Path, a.Executable))
	if e != nil {
		return a, e
	}

	return a, nil
}
func validateMachO(b []byte) error { return validateMachOType(b, 2) }
func validateMachOType(b []byte, fileType uint32) error {
	slices, err := machSlices(b)
	if err != nil {
		return err
	}
	for _, slice := range slices {
		if err = validateThinMachOType(slice.Data, fileType); err != nil {
			return err
		}
	}
	_, err = consistentSliceEntitlements(slices)
	return err
}
func validateThinMachOType(b []byte, fileType uint32) error {
	if len(b) < 32 || binary.LittleEndian.Uint32(b) != 0xfeedfacf || binary.LittleEndian.Uint32(b[4:]) != 0x100000c || binary.LittleEndian.Uint32(b[12:]) != fileType {
		return failure("Only arm64 iPhone executable and dynamic-library slices are supported")
	}
	// arm64e's capability byte describes its ABI version. Native codesign
	// handles this subtype; no instruction or pointer rewriting is performed.
	if subtype := binary.LittleEndian.Uint32(b[8:]) & 0x00ffffff; subtype != 0 && subtype != 2 {
		return failure("Unsupported arm64 CPU subtype")
	}
	count := binary.LittleEndian.Uint32(b[16:])
	size := uint64(binary.LittleEndian.Uint32(b[20:]))
	if count > 100000 || size > uint64(len(b)-32) {
		return failure("Invalid Mach-O load commands")
	}
	end := 32 + int(size)
	off := 32
	signatures := 0
	iosPlatform := false
	for i := uint32(0); i < count; i++ {
		if off+8 > end {
			return failure("Truncated Mach-O load command")
		}
		cmd := binary.LittleEndian.Uint32(b[off:])
		n := int(binary.LittleEndian.Uint32(b[off+4:]))
		if n < 8 || n%4 != 0 || n > end-off {
			return failure("Invalid Mach-O command size")
		}
		c := b[off : off+n]
		switch cmd {
		case 0x32:
			if n < 24 || binary.LittleEndian.Uint32(c[8:]) != 2 || uint64(binary.LittleEndian.Uint32(c[20:])) > uint64(n-24)/8 {
				return failure("Executable targets a different Apple platform")
			}
			iosPlatform = true
		case 0x25: // LC_VERSION_MIN_IPHONEOS in older iPhone binaries.
			if n < 16 {
				return failure("Invalid iPhone minimum-version command")
			}
			iosPlatform = true
		case 0x24, 0x2f, 0x30:
			return failure("Executable targets a different Apple platform")
		case 0x21, 0x2c:
			if n < 20 || binary.LittleEndian.Uint32(c[16:]) != 0 {
				return failure("Encrypted executables cannot be resigned")
			}
		case 0x1d:
			signatures++
			if signatures > 1 || n < 16 {
				return failure("Invalid or duplicate code signature")
			}
			start := uint64(binary.LittleEndian.Uint32(c[8:]))
			length := uint64(binary.LittleEndian.Uint32(c[12:]))
			if start > uint64(len(b)) || length > uint64(len(b))-start {
				return failure("Code signature exceeds executable")
			}
			if e := validateSignature(b[start : start+length]); e != nil {
				return e
			}
		}
		off += n
	}
	if off != end {
		return failure("Mach-O load command sizes disagree")
	}
	if !iosPlatform {
		return failure("Executable does not declare an iPhone device platform")
	}
	return nil
}
func validateSignature(b []byte) error {
	ent, err := signatureEntitlements(b)
	if err != nil {
		return err
	}
	return basicEntitlements(ent)
}
func signatureEntitlements(b []byte) (map[string]any, error) {
	if len(b) < 12 || binary.BigEndian.Uint32(b) != 0xfade0cc0 {
		return nil, failure("Unsupported code signature container")
	}
	length := uint64(binary.BigEndian.Uint32(b[4:]))
	count := uint64(binary.BigEndian.Uint32(b[8:]))
	if length > uint64(len(b)) || length < 12 || count > (length-12)/8 {
		return nil, failure("Malformed code signature index")
	}
	seen := map[uint32]bool{}
	var xml, der map[string]any
	for i := uint64(0); i < count; i++ {
		p := 12 + i*8
		slot := binary.BigEndian.Uint32(b[p:])
		off := uint64(binary.BigEndian.Uint32(b[p+4:]))
		if off < 12+count*8 || off+8 > length {
			return nil, failure("Malformed signature slot")
		}
		n := uint64(binary.BigEndian.Uint32(b[off+4:]))
		if n < 8 || n > length-off {
			return nil, failure("Malformed signature blob")
		}
		if slot != 5 && slot != 7 {
			continue
		}
		if seen[slot] {
			return nil, failure("Duplicate entitlement signature slot")
		}
		seen[slot] = true
		magic := binary.BigEndian.Uint32(b[off:])
		var e error
		if slot == 5 {
			if magic != 0xfade7171 {
				return nil, failure("Unexpected XML entitlement format")
			}
			xml, e = dictionary(b[off+8 : off+n])
		} else {
			if magic != 0xfade7172 {
				return nil, failure("Unexpected DER entitlement format")
			}
			der, e = derEntitlements(b[off+8 : off+n])
		}
		if e != nil {
			return nil, e
		}
	}
	if xml != nil && der != nil && !reflect.DeepEqual(xml, der) {
		return nil, failure("Existing XML and DER entitlements disagree")
	}
	if xml == nil {
		xml = der
	}
	return xml, nil
}
func basicEntitlements(m map[string]any) error {
	for k, v := range m {
		switch k {
		case "application-identifier", "com.apple.developer.team-identifier":
			s, ok := v.(string)
			if !ok || !validText(s) {
				return failure("Malformed existing identity entitlement")
			}
		case "get-task-allow":
			if _, ok := v.(bool); !ok {
				return failure("Malformed existing debug entitlement")
			}
		case networkExtensionKey:
			if _, err := requestedNetwork(m); err != nil {
				return err
			}
		case "keychain-access-groups", "com.apple.security.application-groups":
			// Sharing values are parsed as typed requests and independently authorized
			// by each new profile; source entitlements are never copied wholesale.

		default:
			return fmt.Errorf("Input app has capabilities not supported by this signing path")
		}
	}
	_, err := requestedSharing(m)
	return err
}

type derNode struct {
	tag  byte
	data []byte
}

func derNodes(b []byte) ([]derNode, error) {
	var r []derNode
	for len(b) > 0 {
		if len(b) < 2 || b[0]&31 == 31 {
			return nil, failure("Invalid DER entitlement")
		}
		tag := b[0]
		n := int(b[1])
		h := 2
		if n&128 != 0 {
			c := n & 127
			if c == 0 || c > 4 || len(b) < 2+c || b[2] == 0 {
				return nil, failure("Invalid DER length")
			}
			n = 0
			for _, v := range b[2 : 2+c] {
				n = n<<8 | int(v)
			}
			h += c
			if n < 128 {
				return nil, failure("Noncanonical DER length")
			}
		}
		if n > len(b)-h {
			return nil, failure("Truncated DER entitlement")
		}
		r = append(r, derNode{tag, b[h : h+n]})
		b = b[h+n:]
	}
	return r, nil
}
func derValue(n derNode, depth int) (any, error) {
	if depth > 32 {
		return nil, failure("DER entitlement nesting exceeds limit")
	}
	switch n.tag {
	case 12:
		if !utf8.Valid(n.data) {
			return nil, failure("Invalid DER string")
		}
		return string(n.data), nil
	case 1:
		if bytes.Equal(n.data, []byte{0}) {
			return false, nil
		}
		if bytes.Equal(n.data, []byte{255}) {
			return true, nil
		}
	case 0x30:
		children, e := derNodes(n.data)
		if e != nil {
			return nil, e
		}
		a := []any{}
		for _, c := range children {
			v, e := derValue(c, depth+1)
			if e != nil {
				return nil, e
			}
			a = append(a, v)
		}
		return a, nil
	case 0xb0:
		children, e := derNodes(n.data)
		if e != nil {
			return nil, e
		}
		m := map[string]any{}
		for _, c := range children {
			if c.tag != 0x30 {
				return nil, failure("Invalid DER dictionary")
			}
			fields, e := derNodes(c.data)
			if e != nil || len(fields) != 2 || fields[0].tag != 12 {
				return nil, failure("Invalid DER dictionary entry")
			}
			k := string(fields[0].data)
			if _, ok := m[k]; ok {
				return nil, failure("Duplicate DER dictionary entry")
			}
			v, e := derValue(fields[1], depth+1)
			if e != nil {
				return nil, e
			}
			m[k] = v
		}
		return m, nil
	}
	return nil, failure("Unsupported DER entitlement value")
}
func derEntitlements(b []byte) (map[string]any, error) {
	n, e := derNodes(b)
	if e != nil || len(n) != 1 || n[0].tag != 0x70 {
		return nil, failure("Unsupported DER entitlement envelope")
	}
	children, e := derNodes(n[0].data)
	if e != nil || len(children) != 2 || children[0].tag != 2 || !bytes.Equal(children[0].data, []byte{1}) || children[1].tag != 0xb0 {
		return nil, failure("Unsupported DER entitlement version")
	}
	v, e := derValue(children[1], 0)
	if e != nil {
		return nil, e
	}
	return v.(map[string]any), nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.r.Read(b)
}
func readLimited(path string, limit int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || s.Size() > limit {
		return nil, failure("App metadata or executable exceeds the supported size")
	}
	return io.ReadAll(io.LimitReader(f, limit+1))
}
