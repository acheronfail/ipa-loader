//go:build ios

package securestore

import (
	"os"
	"path/filepath"
	"strings"
)

func stableRecordPath(path string) string {
	home, _ := os.UserHomeDir()
	if home != "" && strings.HasPrefix(path, home+string(filepath.Separator)) {
		return "ios-container/" + strings.TrimPrefix(path, home+string(filepath.Separator))
	}
	return path
}
