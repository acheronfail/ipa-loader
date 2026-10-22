//go:build darwin || linux

package platform

import (
	"os"
	"syscall"
)

func owned(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Getuid())
}
func singleLink(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Nlink == 1
}
