package ipa

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Exercise the actual portable binaries shipped for Windows continuation,
// without an SDK, developer account, device, signing or installation.
func TestCommittedPortableFixtureInputs(t *testing.T) {
	directory := filepath.Join("..", "..", "..", "fixtures", "ipas")
	body, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var catalog struct {
		Format   int `json:"format"`
		Fixtures []struct {
			File     string `json:"file"`
			BundleID string `json:"bundle_id"`
			Version  string `json:"version"`
			Build    string `json:"build"`
			Bytes    int    `json:"bytes"`
			SHA256   string `json:"sha256"`
		} `json:"fixtures"`
	}
	if json.Unmarshal(body, &catalog) != nil || catalog.Format != 1 || len(catalog.Fixtures) == 0 {
		t.Fatal("invalid committed fixture catalog")
	}
	seen := map[string]bool{}
	for _, fixture := range catalog.Fixtures {
		if filepath.Base(fixture.File) != fixture.File || filepath.Ext(fixture.File) != ".ipa" || seen[fixture.File] {
			t.Fatal("unsafe or duplicate fixture name")
		}
		seen[fixture.File] = true
		t.Run(fixture.File, func(t *testing.T) {
			path := filepath.Join(directory, fixture.File)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(data)
			if len(data) != fixture.Bytes || hex.EncodeToString(hash[:]) != fixture.SHA256 {
				t.Fatal("committed IPA differs from reviewed checksum")
			}
			info, err := Inspect(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.BundleID != fixture.BundleID || info.Version != fixture.Version || info.Build != fixture.Build {
				t.Fatal("committed app metadata differs from catalog")
			}
		})
	}
	paths, err := filepath.Glob(filepath.Join(directory, "*.ipa"))
	if err != nil || len(paths) != len(seen) {
		t.Fatal("uncatalogued committed IPA")
	}
}
