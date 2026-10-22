// Package releaseaudit validates portable Windows release inventories without
// loading Windows or Apple libraries.
package releaseaudit

import (
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type FileRecord struct {
	Path    string   `json:"path"`
	Size    int64    `json:"size"`
	SHA256  string   `json:"sha256"`
	Imports []string `json:"windows_imports,omitempty"`
}

func systemLibrary(name string) bool {
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, ".dll") || strings.ContainsAny(name, `/\:`) {
		return false
	}
	if strings.HasPrefix(name, "api-ms-win-") || strings.HasPrefix(name, "ext-ms-win-") {
		return true
	}
	switch name {
	case "advapi32.dll", "crypt32.dll", "gdi32.dll", "kernel32.dll", "opengl32.dll", "shell32.dll", "shlwapi.dll", "user32.dll", "ws2_32.dll":
		return true
	}
	return false
}

func inspectExecutable(path string, expected uint16) ([]string, error) {
	image, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer image.Close()
	if image.Machine != expected {
		return nil, errors.New("Release executable has the wrong architecture")
	}
	symbols, err := image.ImportedSymbols()
	if err != nil {
		return nil, err
	}
	unique := map[string]bool{}
	for _, symbol := range symbols {
		_, library, ok := strings.Cut(symbol, ":")
		if !ok {
			return nil, errors.New("Invalid PE import")
		}
		if !systemLibrary(library) {
			return nil, fmt.Errorf("Unpackaged non-system dependency: %s", library)
		}
		unique[strings.ToLower(library)] = true
	}
	var imports []string
	for library := range unique {
		imports = append(imports, library)
	}
	sort.Strings(imports)
	return imports, nil
}

func Inventory(root string) ([]FileRecord, error) {
	var records []FileRecord
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("Release must not contain links")
		}
		if entry.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("Release contains a non-regular file")
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == "release-manifest.json" {
			return nil
		}
		lower := strings.ToLower(filepath.Base(path))
		if strings.HasPrefix(lower, ".env") || strings.HasSuffix(lower, ".dpapi") || strings.HasSuffix(lower, ".mobileprovision") || strings.HasSuffix(lower, ".p12") || strings.HasSuffix(lower, ".pfx") {
			return errors.New("Private state must not enter a release")
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if lower == "openssl" || lower == "openssl.exe" || lower == "zsign" || lower == "zsign.exe" {
			return errors.New("Native signing helper must not enter a pure Go release")
		}
		if strings.EqualFold(filepath.Base(path), "ipa-loader-anisette.exe") {
			return errors.New("Legacy native authentication helper must not enter the release")
		}
		record := FileRecord{Path: relative, Size: info.Size(), SHA256: hex.EncodeToString(hash.Sum(nil))}
		if strings.EqualFold(filepath.Ext(path), ".exe") || strings.EqualFold(filepath.Ext(path), ".dll") {
			machine := uint16(pe.IMAGE_FILE_MACHINE_AMD64)
			record.Imports, err = inspectExecutable(path, machine)
			if err != nil {
				return err
			}
		}
		records = append(records, record)
		return nil
	})
	sort.Slice(records, func(i, j int) bool { return records[i].Path < records[j].Path })
	return records, err
}
