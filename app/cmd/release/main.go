// release selects native or cross-host release recipes. It never runs target
// executables during a cross build.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type build struct {
	target  string
	command []string
}

func plan(host, target string) ([]build, error) {
	if target == "" {
		target = host
	}
	switch strings.ToLower(target) {
	case "mac", "darwin":
		target = "macos"
	case "win":
		target = "windows"
	default:
		target = strings.ToLower(target)
	}
	if target == "all" {
		targets := []string{host}
		switch host {
		case "darwin":
			targets = []string{"macos", "windows", "linux"}
		case "linux":
			targets = []string{"linux", "windows"}
		}
		var result []build
		for _, t := range targets {
			p, e := plan(host, t)
			if e != nil {
				return nil, e
			}
			result = append(result, p...)
		}
		return result, nil
	}
	var command []string
	switch target {
	case "macos":
		if host == "darwin" {
			command = []string{"sh", "scripts/build-macos.sh"}
		}
	case "linux":
		switch host {
		case "linux":
			command = []string{"sh", "scripts/build-linux.sh"}
		case "darwin":
			command = []string{"sh", "scripts/build-linux-container.sh"}
		}
	case "windows":
		switch host {
		case "windows":
			command = []string{"pwsh", "-NoLogo", "-NoProfile", "-File", "scripts/package-windows.ps1"}
		case "linux", "darwin":
			command = []string{"python3", "scripts/package-windows-cross.py"}
		}
	default:
		return nil, fmt.Errorf("unknown release platform %q; choose linux, windows, macos or all", target)
	}
	if command == nil {
		return nil, fmt.Errorf("cannot build %s releases on %s; macOS needs a macOS host, Linux cross-builds need the macOS container recipe", target, host)
	}
	return []build{{target, command}}, nil
}
func run() error {
	dry := flag.Bool("plan", false, "print selected build commands without running them")
	flag.Parse()
	if flag.NArg() > 1 {
		return fmt.Errorf("usage: release [-plan] [linux|windows|macos|all]")
	}
	target := ""
	if flag.NArg() == 1 {
		target = flag.Arg(0)
	}
	builds, err := plan(runtime.GOOS, target)
	if err != nil {
		return err
	}
	for _, b := range builds {
		fmt.Printf("Release %s: %s\n", b.target, strings.Join(b.command, " "))
	}
	if *dry {
		return nil
	}
	for _, b := range builds {
		fmt.Printf("Building %s release\n", b.target)
		cmd := exec.Command(b.command[0], b.command[1:]...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s release failed: %w", b.target, err)
		}
	}
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
