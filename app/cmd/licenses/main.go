// Command licenses retains dependency notices in a local application bundle.
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

func main() {
	if len(os.Args) != 2 {
		panic("license output directory required")
	}
	out := os.Args[1]
	download := exec.Command("go", "mod", "download", "all")
	download.Stdout, download.Stderr = os.Stdout, os.Stderr
	if err := download.Run(); err != nil {
		panic("Could not download dependency notices")
	}
	data, err := exec.Command("go", "list", "-m", "-json", "all").Output()
	if err != nil {
		panic("Could not list dependency notices")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var m struct {
			Path, Version, Dir string
			Main               bool
		}
		err = decoder.Decode(&m)
		if err == io.EOF {
			break
		}
		if err != nil {
			panic(err)
		}
		if m.Main {
			continue
		}
		if m.Dir == "" {
			panic("Missing dependency source for notices: " + m.Path)
		}
		err = filepath.WalkDir(m.Dir, func(path string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if d.IsDir() {
				if strings.HasPrefix(d.Name(), ".") && path != m.Dir {
					return filepath.SkipDir
				}
				return nil
			}
			name := strings.ToUpper(d.Name())
			if !(strings.HasPrefix(name, "LICENSE") || strings.HasPrefix(name, "COPYING") || name == "NOTICE" || name == "AUTHORS") {
				return nil
			}
			info, e := d.Info()
			if e != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
				return nil
			}
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			relative, e := filepath.Rel(m.Dir, path)
			if e != nil {
				return e
			}
			dest := filepath.Join(out, m.Path+"@"+m.Version, relative)
			if e = os.MkdirAll(filepath.Dir(dest), 0755); e != nil {
				return e
			}
			return os.WriteFile(dest, b, 0644)
		})
		if err != nil {
			panic("Could not collect dependency notices")
		}
	}
	// Retain local reference attribution, including public Apple CA material.
	local, err := os.ReadDir("licenses")
	if err != nil {
		panic(err)
	}
	for _, entry := range local {
		if entry.IsDir() {
			continue
		}
		body, err := os.ReadFile(filepath.Join("licenses", entry.Name()))
		if err != nil {
			panic(err)
		}
		destination := filepath.Join(out, "project-reference", entry.Name())
		if err = os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
			panic(err)
		}
		if err = os.WriteFile(destination, body, 0644); err != nil {
			panic(err)
		}
	}
	// Zig's Windows GNU runtime can be linked into the GUI independently of
	// signing. Preserve its bundled runtime notices whenever that compiler is used.
	zig := os.Getenv("ZIG")
	if zig == "" {
		zig, _ = exec.LookPath("zig")
	}
	if zig != "" {
		environment, err := exec.Command(zig, "env").Output()
		if err != nil {
			panic(err)
		}
		match := regexp.MustCompile(`(?:\.lib_dir|"lib_dir")\s*(?:=|:)\s*("(?:\\.|[^"\\])*")`).FindSubmatch(environment)
		if len(match) != 2 {
			panic("Could not locate compiler runtime notices")
		}
		var library string
		if err = json.Unmarshal(match[1], &library); err != nil {
			panic(err)
		}
		for _, relative := range []string{"libc/mingw/COPYING", "libcxx/LICENSE.TXT", "libcxxabi/LICENSE.TXT", "libunwind/LICENSE.TXT"} {
			body, err := os.ReadFile(filepath.Join(library, filepath.FromSlash(relative)))
			if err != nil {
				panic(err)
			}
			destination := filepath.Join(out, "compiler-runtime", filepath.FromSlash(relative))
			if err = os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
				panic(err)
			}
			if err = os.WriteFile(destination, body, 0644); err != nil {
				panic(err)
			}
		}
	}
	var b []byte
	for _, candidate := range []string{filepath.Join(runtime.GOROOT(), "LICENSE"), filepath.Join(runtime.GOROOT(), "..", "LICENSE")} {
		b, err = os.ReadFile(candidate)
		if err == nil {
			break
		}
	}
	if err != nil {
		panic("Could not locate the installed Go license")
	}
	if err = os.MkdirAll(out, 0755); err != nil {
		panic(err)
	}
	if err = os.WriteFile(filepath.Join(out, "Go-LICENSE"), b, 0644); err != nil {
		panic(err)
	}
}
