//go:build windows

package platform

import (
	"os/exec"
	"syscall"
)

func configureHostCommand(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
