//go:build windows || linux || darwin

package platform

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func syntheticSharingPackage(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	names, err := sharingBuildInputs()
	if err != nil {
		t.Fatal(err)
	}
	manifest := sharingBuildManifest{Format: 1, Target: "arm64-ios12.0", Library: sharingLibraryName, Compiler: sharingBuildTool{Version: "synthetic compiler", SHA256: strings.Repeat("a", 64)}, Linker: sharingBuildTool{Version: "synthetic linker", SHA256: strings.Repeat("b", 64)}, Sources: map[string]string{}}
	write := func(path string, body []byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range names {
		body, err := sharingSource.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		manifest.Sources[name] = buildHash(body)
		write(filepath.Join(root, "sources", filepath.FromSlash(name)), body)
	}
	recipe := []byte("synthetic build recipe")
	manifest.RecipeSHA256 = buildHash(recipe)
	write(filepath.Join(root, "sources", sharingRecipe), recipe)
	notice, _ := sharingSource.ReadFile("compat/LICENSE.fishhook")
	write(filepath.Join(root, "LICENSE.fishhook"), notice)
	image := library()
	manifest.LibrarySHA256 = buildHash(image)
	write(filepath.Join(root, sharingLibraryName), image)
	body, _ := json.Marshal(manifest)
	write(filepath.Join(root, "manifest.json"), body)
	return root
}

func TestWindowsSharingPackageIntegrity(t *testing.T) {
	for _, kind := range []string{"valid", "source changed", "library changed", "recipe changed", "notice changed", "cross recipe", "recipe traversal"} {
		t.Run(kind, func(t *testing.T) {
			root := syntheticSharingPackage(t)
			if kind == "cross recipe" || kind == "recipe traversal" {
				manifestPath := filepath.Join(root, "manifest.json")
				body, err := os.ReadFile(manifestPath)
				if err != nil {
					t.Fatal(err)
				}
				var m sharingBuildManifest
				if err = json.Unmarshal(body, &m); err != nil {
					t.Fatal(err)
				}
				m.Recipe = "build-sharing-linux.py"
				if m.Recipe != sharingRecipe {
					if err = os.Rename(filepath.Join(root, "sources", sharingRecipe), filepath.Join(root, "sources", m.Recipe)); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "recipe traversal" {
					m.Recipe = "../build-sharing-linux.py"
				}
				body, err = json.Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(manifestPath, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			filename := ""
			switch kind {
			case "source changed":
				filename = filepath.Join(root, "sources", "compat", "sharing.m")
			case "library changed":
				filename = filepath.Join(root, sharingLibraryName)
			case "recipe changed":
				filename = filepath.Join(root, "sources", sharingRecipe)
			case "notice changed":
				filename = filepath.Join(root, "LICENSE.fishhook")
			}
			if filename != "" {
				if err := os.WriteFile(filename, []byte("modified"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			e := newControllerTestEngine(context.Background(), testPrivateTempDir(t))
			output, err := e.copyWindowsSharingLibrary(root)
			if (err == nil) != (kind == "valid" || kind == "cross recipe") {
				t.Fatal("sharing package integrity boundary failed", err)
			}
			if err == nil {
				body, err := os.ReadFile(output)
				if err != nil || buildHash(body) != buildHash(library()) {
					t.Fatal("copied adapter differs")
				}
			}
		})
	}
}

func TestBuiltWindowsSharingAdapterGraph(t *testing.T) {
	root := os.Getenv("IPA_LOADER_TEST_SHARING_PACKAGE")
	if root == "" {
		t.Skip("explicit source-built sharing package required")
	}
	work := testPrivateTempDir(t)
	e := newControllerTestEngine(context.Background(), work)
	adapter, err := e.copyWindowsSharingLibrary(root)
	if err != nil {
		t.Fatal(err)
	}
	app, err := extractIPA(context.Background(), filepath.Join("..", "..", "..", "fixtures", "ipas", "ipa-loader-sharing-v12-adhoc.ipa"), work)
	if err != nil {
		t.Fatal(err)
	}
	adapterBytes, err := os.ReadFile(adapter)
	if err != nil {
		t.Fatal(err)
	}
	executables := []string{filepath.Join(app.Path, app.Executable)}
	for _, object := range app.Embedded {
		if object.Extension {
			executables = append(executables, object.Executable)
		}
	}
	if len(executables) != 2 {
		t.Fatal("owned sharing host/extension missing")
	}
	for _, executable := range executables {
		body, err := os.ReadFile(executable)
		if err != nil {
			t.Fatal(err)
		}
		body, err = addSharingLoadCommand(body)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(executable, body, 0600); err != nil {
			t.Fatal(err)
		}
		frameworks := filepath.Join(filepath.Dir(executable), "Frameworks")
		if err = os.MkdirAll(frameworks, 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(frameworks, sharingLibraryName), adapterBytes, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err = refreshSigningGraph(e, &app); err != nil {
		t.Fatal(err)
	}
	adapters := 0
	extensionIndex := -1
	for i, object := range app.Embedded {
		if filepath.Base(object.Path) == sharingLibraryName {
			adapters++
			if strings.Contains(object.Path, ".appex") && extensionIndex >= 0 {
				t.Fatal("extension adapter ordered after its parent")
			}
		}
		if object.Extension {
			extensionIndex = i
		}
	}
	if adapters != 2 || extensionIndex < 0 {
		t.Fatal("adapter code objects missing from inside-out signing graph")
	}
}
