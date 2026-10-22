//go:build windows || linux || darwin

package platform

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type sharingBuildManifest struct {
	Format        int               `json:"format"`
	Target        string            `json:"target"`
	Library       string            `json:"library"`
	LibrarySHA256 string            `json:"library_sha256"`
	Compiler      sharingBuildTool  `json:"compiler"`
	Linker        sharingBuildTool  `json:"linker"`
	Recipe        string            `json:"recipe,omitempty"`
	RecipeSHA256  string            `json:"recipe_sha256"`
	Sources       map[string]string `json:"sources"`
}
type sharingBuildTool struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

func sharingBuildInputs() ([]string, error) {
	names := []string{"compat/sharing.m", "compat/fishhook.c", "compat/fishhook.h", "compat/LICENSE.fishhook"}
	err := fs.WalkDir(sharingSource, "compat/windows", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			names = append(names, path)
		}
		return nil
	})
	return names, err
}
func buildHash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func hashText(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && value == strings.ToLower(value)
}
func sharingPackageFile(path string, limit int64) ([]byte, error) {
	stat, err := os.Lstat(path)
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > limit {
		return nil, failure("Sharing adapter package has a missing, linked or oversized file")
	}
	return os.ReadFile(path)
}

func (h *desktopHost) sharingLibrary(e *engine) (string, error) {
	if runtime.GOOS == "darwin" {
		return e.buildDarwinSharingLibrary()
	}
	root := filepath.Join(h.runtimeRoot, sharingRuntimeDir)
	return e.copyWindowsSharingLibrary(root)
}
func (e *engine) copyWindowsSharingLibrary(root string) (string, error) {
	if err := e.ctx.Err(); err != nil {
		return "", err
	}
	body, err := sharingPackageFile(filepath.Join(root, "manifest.json"), 128<<10)
	if err != nil {
		return "", failure("Build the sharing adapter with scripts/" + sharingRecipe + " before installing apps that use shared groups")
	}
	var manifest sharingBuildManifest
	decoder := json.NewDecoder(bytes.NewReader(bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf})))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || manifest.Format != 1 || manifest.Target != "arm64-ios12.0" || manifest.Library != sharingLibraryName || !hashText(manifest.LibrarySHA256) || !hashText(manifest.RecipeSHA256) || !hashText(manifest.Compiler.SHA256) || !hashText(manifest.Linker.SHA256) || !validText(manifest.Compiler.Version) || !validText(manifest.Linker.Version) {
		return "", failure("Sharing adapter manifest is invalid; rebuild it")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return "", failure("Sharing adapter manifest contains extra content")
	}
	names, err := sharingBuildInputs()
	if err != nil {
		return "", err
	}
	if len(manifest.Sources) != len(names) {
		return "", failure("Sharing adapter source inventory does not match this app")
	}
	for _, name := range names {
		compiled, err := sharingSource.ReadFile(name)
		if err != nil {
			return "", err
		}
		packaged, err := sharingPackageFile(filepath.Join(root, "sources", filepath.FromSlash(name)), 1<<20)
		if err != nil {
			return "", err
		}
		if manifest.Sources[name] != buildHash(compiled) || !bytes.Equal(compiled, packaged) {
			return "", failure("Sharing adapter source does not match this app; rebuild it")
		}
	}
	recipeName := manifest.Recipe
	if recipeName == "" {
		recipeName = sharingRecipe
	}
	if recipeName != "build-sharing-linux.py" && recipeName != "build-sharing-windows.ps1" && recipeName != "build-sharing-macos.go" {
		return "", failure("Unsupported sharing adapter recipe")
	}
	recipe, err := sharingPackageFile(filepath.Join(root, "sources", recipeName), 128<<10)
	if err != nil || buildHash(recipe) != manifest.RecipeSHA256 {
		return "", failure("Sharing adapter rebuild recipe changed")
	}
	license, err := sharingPackageFile(filepath.Join(root, "LICENSE.fishhook"), 1<<20)
	if err != nil {
		return "", err
	}
	notice, _ := sharingSource.ReadFile("compat/LICENSE.fishhook")
	if !bytes.Equal(license, notice) {
		return "", failure("Sharing adapter dependency notice is missing")
	}
	library, err := sharingPackageFile(filepath.Join(root, sharingLibraryName), 8<<20)
	if err != nil || buildHash(library) != manifest.LibrarySHA256 {
		return "", failure("Sharing adapter checksum does not match its build manifest")
	}
	directory := filepath.Join(e.work, "sharing-build")
	if err = privateDir(directory); err != nil {
		return "", err
	}
	output := filepath.Join(directory, sharingLibraryName)
	if err = exclusive(output, library); err != nil {
		return "", err
	}
	if err = inspectMachO(output, 6); err != nil {
		return "", err
	}
	return output, nil
}
