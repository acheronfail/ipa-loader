//go:build darwin

package mobiledevice

import "context"

// DarwinDevice is a route reported by macOS's built-in usbmuxd service.
type DarwinDevice = WindowsDevice

func DarwinDevices(ctx context.Context) ([]DarwinDevice, error)   { return WindowsDevices(ctx) }
func DarwinLocked(ctx context.Context, udid string) (bool, error) { return WindowsLocked(ctx, udid) }
func DarwinInstalledApps(ctx context.Context, udid string) ([]map[string]any, error) {
	return WindowsInstalledApps(ctx, udid)
}
