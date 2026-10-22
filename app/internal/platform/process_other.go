//go:build !windows

package platform

import "os/exec"

func configureHostCommand(*exec.Cmd) {}
