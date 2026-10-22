//go:build !windows

package platform

import "os"

func signedArchiveMode(_ string, info os.FileInfo) (os.FileMode, error) { return info.Mode(), nil }
