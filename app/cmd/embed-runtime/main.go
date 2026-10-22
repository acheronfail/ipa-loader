// embed-runtime packs explicitly selected release trees; symlinks are forbidden.
package main

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: embed-runtime output.zip tree...")
	}
	out, err := os.Create(os.Args[1])
	if err != nil {
		return err
	}
	z := zip.NewWriter(out)
	for _, root := range os.Args[2:] {
		err = filepath.WalkDir(root, func(p string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if d.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("symlink in runtime: %s", p)
			}
			if d.IsDir() {
				return nil
			}
			s, e := d.Info()
			if e != nil {
				return e
			}
			if !s.Mode().IsRegular() {
				return fmt.Errorf("nonregular runtime member")
			}
			rel, e := filepath.Rel(filepath.Dir(root), p)
			if e != nil {
				return e
			}
			h := &zip.FileHeader{Name: filepath.ToSlash(rel), Method: zip.Deflate}
			h.SetModTime(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
			mode := fs.FileMode(0600)
			if s.Mode()&0111 != 0 {
				mode = 0700
			}
			h.SetMode(mode)
			w, e := z.CreateHeader(h)
			if e != nil {
				return e
			}
			r, e := os.Open(p)
			if e != nil {
				return e
			}
			defer r.Close()
			_, e = io.Copy(w, r)
			return e
		})
		if err != nil {
			return err
		}
	}
	if err = z.Close(); err != nil {
		return err
	}
	return out.Close()
}
