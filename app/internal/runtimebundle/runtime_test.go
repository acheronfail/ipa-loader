//go:build linux || windows

package runtimebundle

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func archive(t *testing.T, name string) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	h := &zip.FileHeader{Name: name}
	h.SetMode(0700)
	w, e := z.CreateHeader(h)
	if e != nil {
		t.Fatal(e)
	}
	w.Write([]byte("helper"))
	z.Close()
	return b.Bytes()
}
func TestExtractionReuseAndTampering(t *testing.T) {
	b := archive(t, "signing/tool")
	base := filepath.Join(t.TempDir(), "ipa-loader", "runtime")
	root, e := extract(b, base)
	if e != nil {
		t.Fatal(e)
	}
	again, e := extract(b, base)
	if e != nil || again != root {
		t.Fatal(again, e)
	}
	if e = os.WriteFile(filepath.Join(root, "signing/tool"), []byte("edited"), 0700); e != nil {
		t.Fatal(e)
	}
	if _, e = extract(b, base); e == nil {
		t.Fatal("accepted modified helper")
	}
}
func TestConcurrentExtraction(t *testing.T) {
	b := archive(t, "signing/tool")
	base := filepath.Join(t.TempDir(), "ipa-loader", "runtime")
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := extract(b, base); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
}
func TestRejectTraversal(t *testing.T) {
	for _, name := range []string{"../outside", "a/../../outside", "C:/outside", "a\\outside"} {
		if _, e := extract(archive(t, name), filepath.Join(t.TempDir(), "ipa-loader", "runtime")); e == nil {
			t.Errorf("accepted %s", name)
		}
	}
}
func TestRejectSymlink(t *testing.T) {
	b := archive(t, "signing/tool")
	base := filepath.Join(t.TempDir(), "ipa-loader", "runtime")
	root, e := extract(b, base)
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(root, "signing/tool")
	if e = os.Remove(p); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(filepath.Join(t.TempDir(), "other"), p); e != nil {
		t.Skip(e)
	}
	if _, e = extract(b, base); e == nil {
		t.Fatal("accepted symlink")
	}
}
