//go:build !darwin && !linux

package platform

import "os"

func owned(os.FileInfo) bool      { return false }
func singleLink(os.FileInfo) bool { return false }
