//go:build linux || darwin

package mobiledevice

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"howett.net/plist"
)

func TestUnixMuxUnixSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mux")
	t.Setenv("IPA_LOADER_USBMUXD_SOCKET", path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	conn, err := muxSocket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	peer.Close()
}

// Exercise discovery through a real Unix socket, including mux Connect's
// network-order port and the switch to big-endian lockdown plist framing.
func TestUnixDiscoveryThroughMuxSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mux")
	t.Setenv("IPA_LOADER_USBMUXD_SOCKET", path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 2; i++ {
			conn, e := listener.Accept()
			if e != nil {
				done <- e
				return
			}
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			e = func() error {
				defer conn.Close()
				var header [16]byte
				if _, e := io.ReadFull(conn, header[:]); e != nil {
					return e
				}
				size := binary.LittleEndian.Uint32(header[:])
				if size < 16 || size > 65536 {
					return errors.New("invalid request length")
				}
				data := make([]byte, size-16)
				if _, e := io.ReadFull(conn, data); e != nil {
					return e
				}
				var request map[string]any
				if _, e := plist.Unmarshal(data, &request); e != nil {
					return e
				}
				response := map[string]any{"MessageType": "Result", "Number": uint64(0)}
				if i == 0 {
					if request["MessageType"] != "ListDevices" {
						return errors.New("expected device list request")
					}
					response = map[string]any{"DeviceList": []any{map[string]any{"DeviceID": uint64(7), "Properties": map[string]any{"SerialNumber": "synthetic-iphone", "ConnectionType": "USB"}}}}
				} else if request["MessageType"] != "Connect" || request["DeviceID"] != uint64(7) || request["PortNumber"] != uint64(0x7ef2) {
					return errors.New("incorrect mux connection or port byte order")
				}
				body, e := plist.Marshal(response, plist.XMLFormat)
				if e != nil {
					return e
				}
				binary.LittleEndian.PutUint32(header[:], uint32(16+len(body)))
				if e = writeAll(conn, append(header[:], body...)); e != nil {
					return e
				}
				if i == 1 {
					r, e := readDevicePlist(conn)
					if e != nil {
						return e
					}
					if r["Request"] != "GetValue" {
						return errors.New("expected lockdown GetValue")
					}
					return sendDevicePlist(conn, map[string]any{"Value": map[string]any{"ProductType": "iPhone17,1", "DeviceName": "Synthetic iPhone", "ProductVersion": "18.0"}})
				}
				return nil
			}()
			if e != nil {
				done <- e
				return
			}
		}
		done <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	devices, err := WindowsDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].Name != "Synthetic iPhone" || devices[0].Transport != "USB" {
		t.Fatal("incorrect discovered identity")
	}
}

func TestUnixMuxSocketConfigurationAndCancellation(t *testing.T) {
	t.Setenv("IPA_LOADER_USBMUXD_SOCKET", "relative")
	if _, err := muxSocket(context.Background()); err == nil {
		t.Fatal("accepted relative socket")
	}
	t.Setenv("IPA_LOADER_USBMUXD_SOCKET", filepath.Join(t.TempDir(), "absent"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := muxSocket(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}
