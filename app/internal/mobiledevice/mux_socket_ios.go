//go:build ios

package mobiledevice

import (
	"context"
	"errors"
	"net"
)

func muxSocket(context.Context) (net.Conn, error) {
	return nil, errors.New("Finish desktop setup with Install IPA Loader, then reopen this app")
}
