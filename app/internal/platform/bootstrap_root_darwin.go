//go:build darwin && !ios

package platform

import (
	"os"
	"path/filepath"
)

func loaderRuntimeRoot() (string, error) {
	p, e := os.Executable()
	return filepath.Join(filepath.Dir(filepath.Dir(p)), "Resources"), e
}
