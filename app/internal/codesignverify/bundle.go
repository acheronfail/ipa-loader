package codesignverify

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"howett.net/plist"
)

func (v *verifier) image(filename string, info, resources []byte, identifier string) error {
	if _, exists := v.images[filename]; exists {
		return nil
	}
	if err := v.ctx.Err(); err != nil {
		return err
	}
	data, err := boundedFile(filename, 512<<20)
	if err != nil {
		return err
	}
	parts, err := slices(data)
	if err != nil {
		return err
	}
	image := Image{Path: filename, Slices: len(parts), CMSVerified: true}
	expectedTeam := ""
	if len(v.options.CertificateDER) > 0 {
		certificate, err := x509.ParseCertificate(v.options.CertificateDER)
		if err != nil {
			return invalid("invalid expected signing certificate")
		}
		for _, unit := range certificate.Subject.OrganizationalUnit {
			if len(unit) == 10 && strings.IndexFunc(unit, func(r rune) bool { return !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') }) < 0 {
				if expectedTeam != "" && expectedTeam != unit {
					return invalid("ambiguous signing certificate team")
				}
				expectedTeam = unit
			}
		}
	}
	var previousXML, previousDER []byte
	for sliceIndex, part := range parts {
		blobs, limit, err := signature(part)
		if err != nil {
			return err
		}
		if err = checkEntitlements(blobs, v.options.Entitlements, filename == v.root || filepath.Dir(filename) == v.root, v.options.RequireNoEntitlements); err != nil {
			return err
		}
		if image.Slices > 1 {
			if sliceIndex > 0 {
				if !bytes.Equal(previousXML, blobs[5]) || !bytes.Equal(previousDER, blobs[7]) {
					return invalid("entitlements differ across architectures")
				}
			}
			previousXML = blobs[5]
			previousDER = blobs[7]
		}
		slots := []int{0}
		for typ := range blobs {
			if typ >= 0x1000 && typ <= 0x1005 {
				slots = append(slots, int(typ))
			}
		}
		sort.Ints(slots)
		directories := [][]byte{}
		for _, slot := range slots {
			cd := blobs[uint32(slot)]
			hash, err := directory(cd, part, limit, blobs, info, resources)
			if err != nil {
				return err
			}
			if info != nil && u32(cd, 24) < 3 {
				return invalid("bundle metadata or resources are not sealed")
			}
			if expectedTeam != "" {
				if u32(cd, 8) < 0x20200 || u32(cd, 48) == 0 {
					return invalid("CodeDirectory omits the expected signing team")
				}
				at := int(u32(cd, 48))
				end := bytes.IndexByte(cd[at:], 0)
				if end < 0 || string(cd[at:at+end]) != expectedTeam {
					return invalid("CodeDirectory team differs from the signing certificate")
				}
			}
			if identifier != "" {
				at := int(u32(cd, 20))
				end := bytes.IndexByte(cd[at:], 0)
				if end < 0 || string(cd[at:at+end]) != identifier {
					return invalid("CodeDirectory identifier differs from bundle metadata")
				}
			}
			image.CDHashes = append(image.CDHashes, append([]byte{}, hash[:20]...))
			directories = append(directories, cd)
		}
		cms := blobs[0x10000]
		if len(cms) <= 8 {
			image.CMSVerified = false
			if !v.options.AllowAdHoc || u32(blobs[0], 12)&2 == 0 {
				return invalid("developer CMS signature is required")
			}
		} else {
			for _, cd := range directories {
				if u32(cd, 12)&2 != 0 {
					return invalid("CMS signature is marked ad hoc")
				}
			}
			if err = v.cms(cms[8:], directories); err != nil {
				return err
			}
		}
	}
	v.images[filename] = image
	v.report.Images = append(v.report.Images, image)
	return nil
}

func metadata(bundle string) ([]byte, map[string]any, string, error) {
	info, err := boundedFile(filepath.Join(bundle, "Info.plist"), 1<<20)
	if err != nil {
		return nil, nil, "", err
	}
	var dict map[string]any
	if _, err = plist.Unmarshal(info, &dict); err != nil {
		return nil, nil, "", invalid("invalid bundle metadata")
	}
	executable, ok := dict["CFBundleExecutable"].(string)
	if !ok || executable == "" || executable == "." || executable == ".." || strings.ContainsAny(executable, "/\\:\x00\r\n") {
		return nil, nil, "", invalid("unsafe bundle executable")
	}
	return info, dict, filepath.Join(bundle, executable), nil
}

func (v *verifier) bundle(bundle string) error {
	stat, err := os.Lstat(bundle)
	if err != nil || !stat.IsDir() || stat.Mode()&os.ModeSymlink != 0 {
		return invalid("bundle root must be an ordinary directory")
	}
	info, dict, executable, err := metadata(bundle)
	if err != nil {
		return err
	}
	identifier, ok := dict["CFBundleIdentifier"].(string)
	if !ok || identifier == "" {
		return invalid("missing bundle identifier")
	}
	if bundle == v.root && v.options.Identifier != "" && identifier != v.options.Identifier {
		return invalid("bundle identifier differs from expected signing identifier")
	}
	resources, err := boundedFile(filepath.Join(bundle, "_CodeSignature", "CodeResources"), 16<<20)
	if err != nil {
		return err
	}
	if err = v.image(executable, info, resources, identifier); err != nil {
		return err
	}
	nested := map[string]bool{}
	err = filepath.WalkDir(bundle, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := v.ctx.Err(); err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return invalid("linked bundle members unsupported")
		}
		if filename == bundle {
			return nil
		}
		if entry.IsDir() {
			switch strings.ToLower(filepath.Ext(filename)) {
			case ".framework", ".appex":
				if err := v.bundle(filename); err != nil {
					return err
				}
				nested[filename] = true
				return filepath.SkipDir
			case ".app", ".xpc":
				return invalid("nested app type unsupported")
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return invalid("special bundle member unsupported")
		}
		if strings.EqualFold(filepath.Ext(filename), ".dylib") {
			return v.image(filename, nil, nil, "")
		}
		return nil
	})
	if err != nil {
		return err
	}
	return v.resources(bundle, executable, resources, nested)
}

func safeResource(root, name string) (string, error) {
	if name == "" || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.ContainsAny(name, "\\:\x00\r\n") {
		return "", invalid("unsafe resource path")
	}
	for _, part := range strings.Split(name, "/") {
		if part == "." || part == ".." || part == "" {
			return "", invalid("unsafe resource path")
		}
	}
	return filepath.Join(root, filepath.FromSlash(name)), nil
}

func (v *verifier) resources(bundle, executable string, data []byte, nested map[string]bool) error {
	var manifest map[string]any
	if _, err := plist.Unmarshal(data, &manifest); err != nil {
		return invalid("invalid resource manifest")
	}
	for key := range manifest {
		if key != "files" && key != "files2" && key != "rules" && key != "rules2" {
			return invalid("unsupported resource manifest section")
		}
	}
	covered := map[string]bool{}
	sealedNested := map[string]bool{}
	for _, section := range []string{"files", "files2"} {
		entries, ok := manifest[section].(map[string]any)
		if !ok {
			return invalid("missing resource hash table")
		}
		for relative, raw := range entries {
			filename, err := safeResource(bundle, relative)
			if err != nil {
				return err
			}
			seal, ok := raw.(map[string]any)
			if !ok {
				if hash, yes := raw.([]byte); yes {
					seal = map[string]any{"hash": hash}
				} else {
					return invalid("unsupported resource seal")
				}
			}
			for key := range seal {
				if key != "hash" && key != "hash2" && key != "optional" && key != "cdhash" && key != "requirement" {
					return invalid("unsupported resource seal field")
				}
			}
			optional := false
			if value, exists := seal["optional"]; exists {
				var yes bool
				optional, yes = value.(bool)
				if !yes {
					return invalid("invalid optional resource flag")
				}
			}
			stat, err := os.Lstat(filename)
			if os.IsNotExist(err) && optional {
				continue
			}
			if err != nil {
				return invalid("sealed resource missing")
			}
			if stat.Mode()&os.ModeSymlink != 0 {
				return invalid("linked resource unsupported")
			}
			if raw, exists := seal["cdhash"]; exists {
				if _, exists := seal["hash"]; exists {
					return invalid("mixed file and nested code seal unsupported")
				}
				if _, exists := seal["hash2"]; exists {
					return invalid("mixed file and nested code seal unsupported")
				}
				hash, ok := raw.([]byte)
				if !ok || len(hash) != 20 {
					return invalid("invalid nested code hash")
				}
				imagePath := filename
				if stat.IsDir() {
					_, _, imagePath, err = metadata(filename)
					if err != nil {
						return err
					}
				}
				image, exists := v.images[imagePath]
				if !exists {
					return invalid("unverified nested code seal")
				}
				match := false
				for _, actual := range image.CDHashes {
					match = match || bytes.Equal(actual, hash)
				}
				if !match {
					return invalid("nested code hash mismatch")
				}
				sealedNested[filename] = true
				covered[filename] = true
				continue
			}
			if !stat.Mode().IsRegular() {
				return invalid("resource seal does not name a file")
			}
			file, err := os.Open(filename)
			if err != nil {
				return err
			}
			h1, h2 := sha1.New(), sha256.New()
			_, copyErr := io.Copy(io.MultiWriter(h1, h2), contextReader{v.ctx, file})
			closeErr := file.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			recognized := false
			for _, key := range []string{"hash", "hash2"} {
				raw, exists := seal[key]
				if !exists {
					continue
				}
				expected, ok := raw.([]byte)
				if !ok {
					return invalid("invalid resource hash")
				}
				var actual []byte
				if key == "hash" {
					actual = h1.Sum(nil)
				} else {
					actual = h2.Sum(nil)
				}
				if !bytes.Equal(actual, expected) {
					return invalid("resource file hash mismatch")
				}
				recognized = true
				v.report.ResourceHashes++
			}
			if !recognized {
				return invalid("resource entry has no supported hash")
			}
			covered[filename] = true
		}
	}
	// Conservative complete coverage avoids silently trusting unknown resource
	// rule patterns. Unsupported omissions fail closed instead of being ignored.
	return filepath.WalkDir(bundle, func(filename string, entry fs.DirEntry, err error) error {
		if v.ctx.Err() != nil {
			return v.ctx.Err()
		}
		if err != nil {
			return err
		}
		if filename == bundle {
			return nil
		}
		if entry.IsDir() {
			if sealedNested[filename] {
				return filepath.SkipDir
			}
			return nil
		}
		if covered[filename] || filename == executable || filename == filepath.Join(bundle, "Info.plist") || filename == filepath.Join(bundle, "_CodeSignature", "CodeResources") {
			return nil
		}
		return invalid("unsealed resource file")
	})
}
