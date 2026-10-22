//go:build darwin || linux

package platform

import (
	"golang.org/x/sys/unix"
	"math"
)

func availableDiskBytes(path string) (uint64, error) {
	var s unix.Statfs_t
	if err := unix.Statfs(path, &s); err != nil {
		return 0, err
	}
	if s.Bsize <= 0 {
		return 0, failure("Invalid filesystem block size")
	}
	blocks, size := uint64(s.Bavail), uint64(s.Bsize)
	if blocks > math.MaxUint64/size {
		return math.MaxUint64, nil
	}
	return blocks * size, nil
}
