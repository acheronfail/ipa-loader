//go:build windows || linux || darwin

package mobiledevice

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"howett.net/plist"
)

func selectedWindowsTestDevice(t *testing.T, ctx context.Context) *WindowsDevice {
	t.Helper()
	name := os.Getenv("IPA_LOADER_TEST_DEVICE_NAME")
	if name == "" {
		t.Fatal("Set IPA_LOADER_TEST_DEVICE_NAME to the explicitly authorized test iPhone")
	}
	devices, err := WindowsDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var selected *WindowsDevice
	for i := range devices {
		if devices[i].Name != name || os.Getenv("IPA_LOADER_TEST_DEVICE_TRANSPORT") != "" && devices[i].Transport != os.Getenv("IPA_LOADER_TEST_DEVICE_TRANSPORT") {
			continue
		}
		if selected != nil && selected.UDID != devices[i].UDID {
			t.Fatal("Ambiguous selected test iPhone")
		}
		if selected == nil || devices[i].Transport == "USB" {
			selected = &devices[i]
		}
	}
	if selected == nil {
		t.Fatal("Selected test iPhone unavailable")
	}
	t.Logf("Selected test route: %s", selected.Transport)
	return selected
}

func TestWindowsSelectedReadOnly(t *testing.T) {
	if os.Getenv("IPA_LOADER_TEST_WINDOWS_DEVICE") != "1" {
		t.Skip("explicit read-only selected iPhone check")
	}
	checkSelectedReadOnly(t)
}

func checkSelectedReadOnly(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	fox := selectedWindowsTestDevice(t, ctx)
	locked, err := WindowsLocked(ctx, fox.UDID)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Paired lockdown lock query succeeded: locked=%t", locked)
	apps, err := WindowsInstalledApps(ctx, fox.UDID)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Independent user-app inventory succeeded: %d apps", len(apps))
}

func TestWindowsMuxFraming(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		var header [16]byte
		if _, err := io.ReadFull(server, header[:]); err != nil {
			done <- err
			return
		}
		size := binary.LittleEndian.Uint32(header[:])
		if size < 16 || size > 65536 {
			done <- io.ErrUnexpectedEOF
			return
		}
		body := make([]byte, int(size)-16)
		if _, err := io.ReadFull(server, body); err != nil {
			done <- err
			return
		}
		var request map[string]any
		if _, err := plist.Unmarshal(body, &request); err != nil {
			done <- err
			return
		}
		if request["MessageType"] != "ListDevices" {
			done <- io.ErrUnexpectedEOF
			return
		}
		reply, _ := plist.Marshal(map[string]any{"DeviceList": []any{}}, plist.XMLFormat)
		packet := make([]byte, 16+len(reply))
		binary.LittleEndian.PutUint32(packet, uint32(len(packet)))
		binary.LittleEndian.PutUint32(packet[4:], 1)
		binary.LittleEndian.PutUint32(packet[8:], 8)
		binary.LittleEndian.PutUint32(packet[12:], 1)
		copy(packet[16:], reply)
		// Fragment every header/body byte to exercise exact-read behavior.
		for _, b := range packet {
			if _, err := server.Write([]byte{b}); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	response, err := muxExchange(context.Background(), client, map[string]any{"MessageType": "ListDevices"})
	if err != nil {
		t.Fatal(err)
	}
	if list, ok := response["DeviceList"].([]any); !ok || len(list) != 0 {
		t.Fatal("Invalid decoded mux response")
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestWindowsDeviceFrameBounds(t *testing.T) {
	for _, size := range []uint32{0, 8<<20 + 1, 0xffffffff} {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			var header [4]byte
			binary.BigEndian.PutUint32(header[:], size)
			_, _ = server.Write(header[:])
		}()
		_, err := readDevicePlist(client)
		client.Close()
		if err == nil {
			t.Fatalf("Accepted invalid frame size %d", size)
		}
	}
}

func TestWindowsDeviceCancellation(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := deviceExchange(ctx, client, map[string]any{"Request": "GetValue"}); done <- err }()
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("Cancellation returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Cancelled blocked device request did not stop")
	}
}

func TestWindowsMuxRejectsMismatchedTag(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		var header [16]byte
		_, _ = io.ReadFull(server, header[:])
		size := binary.LittleEndian.Uint32(header[:])
		_, _ = io.CopyN(io.Discard, server, int64(size)-16)
		binary.LittleEndian.PutUint32(header[:], 17)
		binary.LittleEndian.PutUint32(header[4:], 1)
		binary.LittleEndian.PutUint32(header[8:], 8)
		binary.LittleEndian.PutUint32(header[12:], 2)
		_, _ = server.Write(header[:])
	}()
	if _, err := muxExchange(context.Background(), client, map[string]any{"MessageType": "ListDevices"}); err == nil {
		t.Fatal("Accepted unrelated mux response tag")
	}
}

func TestWindowsPairingTLSPinsDevicePublicKey(t *testing.T) {
	makeIdentity := func(serial int64) ([]byte, []byte, tls.Certificate) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
		identity, err := tls.X509KeyPair(cert, private)
		if err != nil {
			t.Fatal(err)
		}
		return cert, private, identity
	}
	hostCert, hostKey, _ := makeIdentity(1)
	deviceCert, _, deviceIdentity := makeIdentity(2)
	_, _, wrongIdentity := makeIdentity(3)
	for _, test := range []struct {
		name      string
		identity  tls.Certificate
		wantError bool
	}{{"matching-device", deviceIdentity, false}, {"unpaired-device", wrongIdentity, true}} {
		t.Run(test.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			go func() {
				secure := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{test.identity}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
				_ = secure.HandshakeContext(ctx)
			}()
			conn, err := pairedTLS(ctx, client, map[string]any{"RootCertificate": hostCert, "RootPrivateKey": hostKey, "DeviceCertificate": deviceCert})
			if test.wantError && err == nil {
				conn.Close()
				t.Fatal("Accepted a TLS device key absent from the existing pairing record")
			}
			if !test.wantError && err != nil {
				t.Fatal("Rejected matching pairing certificate", err)
			}
		})
	}
}
