//go:build !darwin && !windows && !linux

package platform

import (
	"context"
	"ipa-loader/app/internal/apple"
)

func Devices(context.Context) ([]Device, error) {
	return nil, failure("Device installation is supported on macOS only")
}
func Sideload(context.Context, *apple.Client, *apple.Session, string, string, Device, func(Progress)) (Result, error) {
	return Result{}, failure("Device installation is supported on macOS only")
}
