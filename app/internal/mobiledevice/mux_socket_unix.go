//go:build linux || (darwin && !ios)

package mobiledevice

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Linux uses the open-source daemon; macOS supplies usbmuxd with the OS.
// lockdown, pinned pairing TLS, AFC and installation proxy stay in Go.
func muxSocket(ctx context.Context) (net.Conn, error) {
	path := os.Getenv("IPA_LOADER_USBMUXD_SOCKET")
	if path == "" {
		path = "/var/run/usbmuxd"
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("The usbmuxd socket path must be absolute")
	}
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", path)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if runtime.GOOS == "darwin" {
			return nil, errors.New("Could not reach the macOS device service; connect and unlock the iPhone, then trust this Mac in Finder")
		}
		return nil, errors.New("Could not reach usbmuxd; install/start usbmuxd, connect the iPhone by USB, and check socket permissions")
	}
	return conn, nil
}
