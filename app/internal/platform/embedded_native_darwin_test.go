//go:build darwin

package platform

import (
	"bytes"
	"context"
	"debug/macho"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func TestNativeEmbeddedSigning(t *testing.T) {
	input := os.Getenv("IPA_LOADER_NATIVE_FRAMEWORK_FIXTURE")
	if input == "" {
		t.Skip("optional native framework fixture check")
	}
	work := t.TempDir()
	app, err := extractIPA(context.Background(), input, work)
	if err != nil {
		t.Fatal(err)
	}
	if len(app.Embedded) != 2 {
		t.Fatal("expected framework and dylib fixture")
	}
	before, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	loads := func(p string) []string {
		f, err := macho.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		libs, err := f.ImportedLibraries()
		if err != nil {
			t.Fatal(err)
		}
		return libs
	}
	imports := map[string][]string{}
	for _, o := range app.Embedded {
		imports[o.Executable] = loads(o.Executable)
	}
	ent := filepath.Join(work, "entitlements.plist")
	if err = os.WriteFile(ent, []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>get-task-allow</key><true/></dict></plist>`), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(filepath.Join(app.Path, app.Executable), 0755); err != nil {
		t.Fatal(err)
	}
	e := newControllerTestEngine(context.Background(), work)
	// Exercise replacement of a previous signature, including stale app-style
	// entitlements that must not survive on libraries signed by this client.
	for _, o := range app.Embedded {
		if err = os.Chmod(o.Executable, 0755); err != nil {
			t.Fatal(err)
		}
		if err = exec.Command("/usr/bin/codesign", "--force", "--sign", "-", "--generate-entitlement-der", "--entitlements", ent, o.Path).Run(); err != nil {
			t.Fatal("could not prepare previously signed library")
		}
	}
	if _, err = inspectCode(context.Background(), app); err != nil {
		t.Fatal(err)
	}
	if err = e.signApp(app, "-", ent); err != nil {
		t.Fatal(err)
	}
	for _, o := range app.Embedded {
		if !reflect.DeepEqual(imports[o.Executable], loads(o.Executable)) {
			t.Fatal("signing changed library dependencies")
		}
		out, err := exec.Command("/usr/bin/codesign", "-d", "--entitlements", "-", o.Path).Output()
		if err != nil || len(bytes.TrimSpace(out)) != 0 {
			t.Fatal("library received app entitlements")
		}
	}
	out, err := exec.Command("/usr/bin/codesign", "-d", "--entitlements", "-", app.Path).Output()
	entitlements, parseErr := dictionary(out)
	if err != nil || parseErr != nil || entitlements["get-task-allow"] != true {
		t.Fatal("main app entitlements missing after embedded signing")
	}
	// Re-discovery must also accept already-signed input, before any account call.
	if _, err = inspectCode(context.Background(), app); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(input)
	if !bytes.Equal(before, after) {
		t.Fatal("source IPA changed")
	}
	resource := filepath.Join(app.Path, "Frameworks", "FixtureKit.framework", "proof.txt")
	if err = os.WriteFile(resource, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = exec.Command("/usr/bin/codesign", "--verify", "--deep", "--strict", app.Path).Run(); err == nil {
		t.Fatal("modified framework resource passed verification")
	}
}
