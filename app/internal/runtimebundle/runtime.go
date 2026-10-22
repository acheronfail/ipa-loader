//go:build linux || windows

// Package runtimebundle materializes release helpers in a content-addressed,
// private user cache. Development builds retain their explicit folder layout.
package runtimebundle

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"ipa-loader/app/internal/securestore"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func Embedded() bool { return len(payload) > 0 }

func Root() (string, error) {
	if len(payload) == 0 {
		exe, err := os.Executable()
		return filepath.Dir(exe), err
	}
	cache, err := os.UserCacheDir()
	if err != nil || !filepath.IsAbs(cache) {
		return "", fmt.Errorf("cannot locate private runtime cache")
	}
	return extract(payload, filepath.Join(cache, "ipa-loader", "runtime"))
}

func extract(data []byte, base string) (string, error) {
	sum := sha256.Sum256(data)
	root := filepath.Join(base, fmt.Sprintf("%x", sum))
	for _, p := range []string{filepath.Dir(base), base} {
		if err := securestore.EnsureDir(p); err != nil {
			return "", err
		}
	}
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", err
	}
	validate := func(dir string) error {
		if err := securestore.CheckDir(dir); err != nil {
			return err
		}
		s, e := os.Lstat(dir)
		if e != nil {
			return e
		}
		if !s.IsDir() || s.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("unsafe runtime cache")
		}
		for _, f := range z.File {
			p, e := member(dir, f)
			if e != nil {
				return e
			}
			// Inspect every parent before opening files; never follow cached symlinks.
			for parent := filepath.Dir(p); parent != dir; parent = filepath.Dir(parent) {
				if err := securestore.CheckDir(parent); err != nil {
					return err
				}
				s, e := os.Lstat(parent)
				if e != nil || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 {
					return fmt.Errorf("unsafe cached runtime parent")
				}
			}
			s, e := os.Lstat(p)
			if e != nil || !s.Mode().IsRegular() || s.Size() != int64(f.UncompressedSize64) || (runtime.GOOS != "windows" && s.Mode().Perm() != f.Mode().Perm()) {
				return fmt.Errorf("cached runtime changed")
			}
			if err := securestore.CheckFile(p); err != nil {
				return err
			}
			a, e := os.Open(p)
			if e != nil {
				return e
			}
			h := sha256.New()
			_, e = io.Copy(h, a)
			a.Close()
			if e != nil {
				return e
			}
			b, e := f.Open()
			if e != nil {
				return e
			}
			expected := sha256.New()
			_, e = io.Copy(expected, b)
			b.Close()
			if e != nil {
				return e
			}
			if !bytes.Equal(h.Sum(nil), expected.Sum(nil)) {
				return fmt.Errorf("cached runtime integrity check failed")
			}
		}
		return nil
	}
	if _, err = os.Lstat(root); err == nil {
		return root, validate(root)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	stage, err := securestore.MkdirTemp(base, ".extract-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(stage)
	for _, f := range z.File {
		p, e := member(stage, f)
		if e != nil {
			return "", e
		}
		if e = securestore.EnsureDir(filepath.Dir(p)); e != nil {
			return "", e
		}
		r, e := f.Open()
		if e != nil {
			return "", e
		}
		w, e := securestore.CreatePrivate(p)
		if e != nil {
			r.Close()
			return "", e
		}
		_, e = io.Copy(w, r)
		r.Close()
		ce := w.Close()
		if e != nil {
			return "", e
		}
		if ce != nil {
			return "", ce
		}
		if e = os.Chmod(p, f.Mode().Perm()); e != nil {
			return "", e
		}
	}
	if err = validate(stage); err != nil {
		return "", err
	}
	if err = os.Rename(stage, root); err != nil {
		if e := validate(root); e != nil {
			return "", err
		}
	}
	return root, validate(root)
}

func member(root string, f *zip.File) (string, error) {
	if f.Name == "" || strings.HasPrefix(f.Name, "/") || strings.ContainsAny(f.Name, "\\:") || !f.Mode().IsRegular() || f.UncompressedSize64 > 128<<20 {
		return "", fmt.Errorf("invalid embedded runtime member")
	}
	p := filepath.Join(root, filepath.FromSlash(f.Name))
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid runtime path")
	}
	return p, nil
}
