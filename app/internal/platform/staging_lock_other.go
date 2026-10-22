//go:build !darwin && !linux && !windows

package platform

func lockStaging(string) (func(), error) {
	return nil, failure("Native installation recovery is not yet supported on this platform")
}
