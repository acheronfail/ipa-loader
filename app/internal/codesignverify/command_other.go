//go:build !windows

package codesignverify

import "os/exec"

func configureCommand(*exec.Cmd) {}
