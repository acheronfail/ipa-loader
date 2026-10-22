// Package ipa reads display metadata without extracting or executing an app.
package ipa

import (
	"archive/zip"
	"bytes"
	"errors"
	"image"
	_ "image/jpeg"
	"image/png"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
	"howett.net/plist"
)

type Info struct {
	Path, Name, BundleID, Version, Build string
	Icon                                 []byte
}

func read(f *zip.File, limit int64) ([]byte, error) {
	if f.UncompressedSize64 > uint64(limit) {
		return nil, errors.New("An IPA metadata file is too large")
	}
	r, err := f.Open()
	if err != nil {
		return nil, errors.New("Could not read the IPA")
	}
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("Could not read the IPA metadata")
	}
	return b, nil
}

func Inspect(filename string) (*Info, error) {
	z, err := zip.OpenReader(filename)
	if err != nil {
		return nil, errors.New("Choose a valid .ipa archive")
	}
	defer z.Close()
	if len(z.File) > 100000 {
		return nil, errors.New("This IPA contains too many files")
	}
	seen, apps := map[string]bool{}, map[string]bool{}
	for _, f := range z.File {
		n := f.Name
		if n == "" || strings.HasPrefix(n, "/") || strings.ContainsAny(n, "\\\x00:") || path.Clean(strings.TrimSuffix(n, "/")) != strings.TrimSuffix(n, "/") || strings.HasPrefix(n, "../") || n == ".." {
			return nil, errors.New("This IPA contains an unsafe file path")
		}
		key := cases.Fold().String(norm.NFC.String(strings.TrimSuffix(n, "/")))
		if seen[key] {
			return nil, errors.New("This IPA contains duplicate file paths")
		}
		seen[key] = true
		if f.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("IPAs containing symbolic links are not supported yet")
		}
		if f.Flags&1 != 0 {
			return nil, errors.New("Password-protected IPA archives are not supported")
		}
		parts := strings.Split(n, "/")
		if len(parts) >= 2 && parts[0] == "Payload" && strings.HasSuffix(parts[1], ".app") {
			apps["Payload/"+parts[1]+"/"] = true
		}
	}
	if len(apps) != 1 {
		return nil, errors.New("The IPA must contain one iPhone app")
	}
	var base string
	for name := range apps {
		base = name
	}
	var metadata map[string]any
	for _, f := range z.File {
		if f.Name == base+"Info.plist" {
			b, e := read(f, 1<<20)
			if e != nil {
				return nil, e
			}
			if _, e = plist.Unmarshal(b, &metadata); e != nil {
				return nil, errors.New("The app's Info.plist could not be read")
			}
			break
		}
	}
	text := func(key string) string {
		s, _ := metadata[key].(string)
		if len(s) > 512 {
			return ""
		}
		return strings.TrimSpace(s)
	}
	info := &Info{Path: filename, Name: text("CFBundleDisplayName"), BundleID: text("CFBundleIdentifier"), Version: text("CFBundleShortVersionString"), Build: text("CFBundleVersion")}
	if info.Name == "" {
		info.Name = text("CFBundleName")
	}
	if info.Name == "" {
		info.Name = strings.TrimSuffix(path.Base(strings.TrimSuffix(base, "/")), ".app")
	}
	if info.BundleID == "" || info.Version == "" || info.Build == "" {
		return nil, errors.New("The IPA is missing its app identifier or version")
	}
	declared := []string{}
	var gather func(any)
	gather = func(v any) {
		switch value := v.(type) {
		case string:
			declared = append(declared, strings.ToLower(strings.TrimSuffix(value, ".png")))
		case []any:
			for _, x := range value {
				gather(x)
			}
		case map[string]any:
			for k, x := range value {
				if k == "CFBundleIconFiles" || k == "CFBundleIconFile" || k == "CFBundlePrimaryIcon" {
					gather(x)
				}
			}
		}
	}
	for _, k := range []string{"CFBundleIconFiles", "CFBundleIconFile", "CFBundleIcons", "CFBundleIcons~ipad"} {
		gather(metadata[k])
	}
	type candidate struct {
		file *zip.File
		rank int
	}
	var candidates []candidate
	for _, f := range z.File {
		if !strings.HasPrefix(f.Name, base) || !strings.HasSuffix(strings.ToLower(f.Name), ".png") {
			continue
		}
		relative := strings.TrimPrefix(f.Name, base)
		if strings.Contains(relative, "/") {
			continue
		}
		name := strings.ToLower(relative)
		rank := 0
		for _, d := range declared {
			if strings.HasPrefix(name, d) {
				rank = 2
				break
			}
		}
		if rank == 0 && (strings.HasPrefix(name, "appicon") || strings.HasPrefix(name, "icon")) {
			rank = 1
		}
		if rank > 0 {
			candidates = append(candidates, candidate{f, rank})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].rank != candidates[j].rank {
			return candidates[i].rank > candidates[j].rank
		}
		return candidates[i].file.Name < candidates[j].file.Name
	})
	best, rank := -1, 0
	for i, c := range candidates {
		if i >= 32 {
			break
		}
		b, e := read(c.file, 10<<20)
		if e != nil {
			continue
		}
		normalized, e := normalizePNG(b)
		if e != nil {
			continue
		}
		config, _, e := image.DecodeConfig(bytes.NewReader(normalized))
		if e != nil {
			continue
		}
		area := config.Width * config.Height
		if c.rank > rank || (c.rank == rank && area > best) {
			info.Icon = normalized
			best = area
			rank = c.rank
		}
	}
	return info, nil
}

func normalizePNG(data []byte) ([]byte, error) {
	if bytes.Contains(data[:min(len(data), 40)], []byte("CgBI")) {
		return decodeCgBI(data)
	}
	config, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || config.Width <= 0 || config.Height <= 0 || config.Width > 2048 || config.Height > 2048 {
		return nil, errors.New("Unsupported app icon")
	}
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	err = png.Encode(&out, img)
	return out.Bytes(), err
}
