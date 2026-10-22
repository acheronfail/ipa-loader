//go:build !windows && !linux && !darwin

package mobiledevice

import "context"

func openConfiguredNative(ctx context.Context, options Options) (wire, error) {
	return nil, ErrUnavailable
}
