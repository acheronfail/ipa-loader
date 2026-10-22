//go:build !darwin && !linux && !windows

package platform

import "math"

// Installation is unsupported here. Keep portable archive inspection usable;
// the future platform backend must implement its own disk-space query.
func availableDiskBytes(string) (uint64, error) { return math.MaxUint64, nil }
