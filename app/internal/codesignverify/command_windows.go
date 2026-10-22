//go:build windows

package codesignverify

import (
	"os/exec"
	"syscall"
)

func configureCommand(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} }
