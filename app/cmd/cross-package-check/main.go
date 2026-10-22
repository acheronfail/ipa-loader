// cross-package-check audits Windows files as data on a POSIX host.
package main

import (
	"bytes"
	"crypto/sha256"
	"debug/macho"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"ipa-loader/app/internal/releaseaudit"
	"os"
	"path/filepath"
)

func hash(p string) (string, error) {
	b, e := os.ReadFile(p)
	if e != nil {
		return "", e
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}
func check(p, want string) error {
	got, e := hash(p)
	if e != nil {
		return e
	}
	if len(want) != 64 || got != want {
		return fmt.Errorf("runtime hash mismatch: %s", p)
	}
	return nil
}
func run() error {
	root := flag.String("root", "", "Windows package root")
	flag.Parse()
	if *root == "" {
		return fmt.Errorf("select package root")
	}
	records, e := releaseaudit.Inventory(*root)
	if e != nil {
		return e
	}
	var sharing struct {
		Format                  int
		Target, Library, Recipe string
		LibraryHash             string `json:"library_sha256"`
		RecipeHash              string `json:"recipe_sha256"`
		Sources                 map[string]string
	}
	p := filepath.Join(*root, "sharing-windows")
	b, e := os.ReadFile(filepath.Join(p, "manifest.json"))
	if e != nil {
		return e
	}
	if e = json.Unmarshal(b, &sharing); e != nil {
		return e
	}
	if sharing.Format != 1 || sharing.Target != "arm64-ios12.0" || sharing.Library != "IPALoaderSharingCompat-v1.dylib" || sharing.Recipe != "build-sharing-linux.py" {
		return fmt.Errorf("invalid sharing provenance")
	}
	if e = check(filepath.Join(p, sharing.Library), sharing.LibraryHash); e != nil {
		return e
	}
	if e = check(filepath.Join(p, "sources", sharing.Recipe), sharing.RecipeHash); e != nil {
		return e
	}
	names := []string{"compat/sharing.m", "compat/fishhook.c", "compat/fishhook.h", "compat/LICENSE.fishhook"}
	e = filepath.WalkDir("internal/platform/compat/windows", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			name, err := filepath.Rel("internal/platform", path)
			if err != nil {
				return err
			}
			names = append(names, filepath.ToSlash(name))
		}
		return nil
	})
	if e != nil {
		return e
	}
	if len(names) != len(sharing.Sources) {
		return fmt.Errorf("sharing source inventory mismatch")
	}
	for _, name := range names {
		want := sharing.Sources[name]
		if e = check(filepath.Join(p, "sources", filepath.FromSlash(name)), want); e != nil {
			return e
		}
		if e = check(filepath.Join("internal/platform", filepath.FromSlash(name)), want); e != nil {
			return e
		}
	}
	a, e := os.ReadFile(filepath.Join(p, "LICENSE.fishhook"))
	if e != nil {
		return e
	}
	b, e = os.ReadFile("internal/platform/compat/LICENSE.fishhook")
	if e != nil || !bytes.Equal(a, b) {
		return fmt.Errorf("sharing notice mismatch")
	}
	image, e := macho.Open(filepath.Join(p, sharing.Library))
	if e != nil {
		return e
	}
	defer image.Close()
	if image.Cpu != macho.CpuArm64 || image.Type != macho.TypeDylib {
		return fmt.Errorf("invalid sharing Mach-O")
	}
	for _, name := range []string{"ipa-loader.exe", "licenses/Go-LICENSE"} {
		if _, e = os.Stat(filepath.Join(*root, name)); e != nil {
			return e
		}
	}
	data, e := json.MarshalIndent(struct {
		Format   int                       `json:"format"`
		Platform string                    `json:"platform"`
		Files    []releaseaudit.FileRecord `json:"files"`
	}{1, "windows/amd64", records}, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(*root, "release-manifest.json"), append(data, '\n'), 0644); e != nil {
		return e
	}
	fmt.Printf("Windows cross-package verified: %d files, native hashes/sources and system PE imports; runtime acceptance pending.\n", len(records))
	return nil
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
