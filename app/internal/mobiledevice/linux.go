//go:build linux

package mobiledevice

import "context"

// LinuxDevice is an observed usbmuxd route, not a fabricated connection.
type LinuxDevice = WindowsDevice

func LinuxDevices(ctx context.Context) ([]LinuxDevice, error)    { return WindowsDevices(ctx) }
func LinuxLocked(ctx context.Context, udid string) (bool, error) { return WindowsLocked(ctx, udid) }
func LinuxInstalledApps(ctx context.Context, udid string) ([]map[string]any, error) {
	return WindowsInstalledApps(ctx, udid)
}
func LinuxReadAppDocument(ctx context.Context, udid, bundleID, relative string, options DocumentOptions) ([]byte, error) {
	return WindowsReadAppDocument(ctx, udid, bundleID, relative, options)
}
