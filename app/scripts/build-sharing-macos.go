//go:build ignore

// Build the iOS sharing adapter once during macOS packaging. Only the build
// host needs Xcode; the released application copies and signs this adapter.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func read(path string) []byte { b, err := os.ReadFile(path); must(err); return b }
func command(name string, args ...string) string {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		panic(fmt.Sprintf("%s: %v\n%s", name, err, out))
	}
	return strings.TrimSpace(string(out))
}
func main() {
	if len(os.Args) != 2 {
		panic("usage: go run scripts/build-sharing-macos.go output-directory (from app/)")
	}
	out, err := filepath.Abs(os.Args[1])
	must(err)
	must(os.MkdirAll(filepath.Join(out, "sources"), 0755))
	const library = "IPALoaderSharingCompat-v1.dylib"
	clang := command("/usr/bin/xcrun", "--find", "clang")
	linker := command("/usr/bin/xcrun", "--find", "ld")
	sdk := command("/usr/bin/xcrun", "--sdk", "iphoneos", "--show-sdk-path")
	command(clang, "-target", "arm64-apple-ios12.0", "-isysroot", sdk, "-dynamiclib", "-fobjc-arc", "-O2", "-framework", "Foundation", "-framework", "Security", "-Wl,-no_adhoc_codesign", "-Wl,-install_name,@rpath/"+library, "internal/platform/compat/sharing.m", "internal/platform/compat/fishhook.c", "-o", filepath.Join(out, library))
	sources := map[string]string{}
	names := []string{"compat/sharing.m", "compat/fishhook.c", "compat/fishhook.h", "compat/LICENSE.fishhook"}
	must(filepath.WalkDir("internal/platform/compat/windows", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			relative, err := filepath.Rel("internal/platform", path)
			if err != nil {
				return err
			}
			names = append(names, filepath.ToSlash(relative))
		}
		return nil
	}))
	for _, name := range names {
		data := read(filepath.Join("internal/platform", name))
		destination := filepath.Join(out, "sources", name)
		must(os.MkdirAll(filepath.Dir(destination), 0755))
		must(os.WriteFile(destination, data, 0644))
		sources[name] = hash(data)
	}
	const recipe = "build-sharing-macos.go"
	recipeData := read(filepath.Join("scripts", recipe))
	must(os.WriteFile(filepath.Join(out, "sources", recipe), recipeData, 0644))
	must(os.WriteFile(filepath.Join(out, "LICENSE.fishhook"), read("internal/platform/compat/LICENSE.fishhook"), 0644))
	manifest := map[string]any{
		"format": 1, "target": "arm64-ios12.0", "library": library, "library_sha256": hash(read(filepath.Join(out, library))),
		"compiler": map[string]string{"version": strings.Split(command(clang, "--version"), "\n")[0], "sha256": hash(read(clang))},
		"linker":   map[string]string{"version": strings.Split(command(linker, "-version_details"), "\n")[0], "sha256": hash(read(linker))},
		"recipe":   recipe, "recipe_sha256": hash(recipeData), "sources": sources,
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(out, "manifest.json"), append(data, '\n'), 0644))
	fmt.Println("Built sharing adapter:", out)
}
