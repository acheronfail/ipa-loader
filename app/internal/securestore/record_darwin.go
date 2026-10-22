//go:build darwin && !ios

package securestore

func stableRecordPath(path string) string { return path }
