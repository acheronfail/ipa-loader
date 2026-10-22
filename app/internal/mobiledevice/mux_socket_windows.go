//go:build windows

package mobiledevice

import (
	"context"
	"errors"
	"net"
	"time"
)

func muxSocket(ctx context.Context) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", "127.0.0.1:27015")
	if err != nil {
		return nil, errors.New("Could not reach Apple Mobile Device Service; install Apple's device support and start its service")
	}
	return conn, nil
}
