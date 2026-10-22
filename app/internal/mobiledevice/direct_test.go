//go:build darwin || linux || windows

package mobiledevice

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"howett.net/plist"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDirectRouteRejectsIncompletePairingBeforeConnecting(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte("invalid"), func() []byte {
		b, _ := plist.Marshal(map[string]any{"HostID": "host", "SystemBUID": "buid", "RootCertificate": []byte("invalid"), "RootPrivateKey": []byte("invalid"), "DeviceCertificate": []byte("invalid")}, plist.XMLFormat)
		return b
	}()} {
		if err := ConfigureDirectDevice(DirectDevice{UDID: "device", Address: "10.7.0.1", PairRecord: raw}); err == nil {
			t.Fatal("accepted unusable credentials")
		}
	}
	for _, address := range []string{"8.8.8.8", "127.0.0.1", "10.7.0.1:62078", "https://10.7.0.1", "::1"} {
		if err := ConfigureDirectDevice(DirectDevice{UDID: "device", Address: address}); err == nil {
			t.Fatal("accepted non-VPN address")
		}
	}
	if _, err := (&DirectDevice{UDID: "owned"}).session(context.Background(), "different"); err == nil || !strings.Contains(err.Error(), "another device") {
		t.Fatal("wrong-device session not rejected before I/O")
	}
	if currentDirect() != nil {
		t.Fatal("failed configuration changed the active device route")
	}
}

func TestDirectConnectionFailureMatchesVPNVariant(t *testing.T) {
	// An invalid numeric address fails before reaching the network.
	for _, builtin := range []bool{false, true} {
		d := DirectDevice{Address: "invalid:address", BuiltInVPN: builtin}
		_, err := d.dial(context.Background(), 62078)
		if err == nil {
			t.Fatal("invalid address connected")
		}
		message := err.Error()
		if builtin {
			if !strings.Contains(message, "Enable Local VPN") || strings.Contains(message, "LocalDevVPN") {
				t.Fatalf("wrong built-in VPN guidance: %s", message)
			}
		} else if !strings.Contains(message, "LocalDevVPN") || !strings.Contains(message, "Device IP") {
			t.Fatalf("wrong external VPN guidance: %s", message)
		}
	}
}

func TestDirectSessionRequiresTLSAndMatchingHardwareIdentity(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	encoded, _ := x509.MarshalPKCS8PrivateKey(key)
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
	identity, err := tls.X509KeyPair(cert, private)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"matching", "wrong hardware", "no TLS", "pair denied"} {
		t.Run(kind, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				request, err := readDevicePlist(server)
				if err != nil {
					done <- err
					return
				}
				if request["Request"] != "StartSession" || request["HostID"] != "host" || request["SystemBUID"] != "buid" {
					done <- fmt.Errorf("wrong session identity")
					return
				}
				response := map[string]any{"SessionID": "session", "EnableSessionSSL": kind != "no TLS"}
				if kind == "pair denied" {
					response = map[string]any{"Error": "InvalidHostID"}
				}
				if err = sendDevicePlist(server, response); err != nil {
					done <- err
					return
				}
				if kind == "no TLS" || kind == "pair denied" {
					done <- nil
					return
				}
				secure := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{identity}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
				if err = secure.HandshakeContext(ctx); err != nil {
					done <- err
					return
				}
				request, err = readDevicePlist(secure)
				if err != nil {
					done <- err
					return
				}
				if request["Key"] != "UniqueDeviceID" {
					done <- fmt.Errorf("did not check hardware identity")
					return
				}
				udid := "owned"
				if kind == "wrong hardware" {
					udid = "other"
				}
				done <- sendDevicePlist(secure, map[string]any{"Value": udid})
			}()
			pair := map[string]any{"HostID": "host", "SystemBUID": "buid", "RootCertificate": cert, "RootPrivateKey": private, "DeviceCertificate": cert}
			s, err := (&DirectDevice{UDID: "owned", Address: "10.7.0.1"}).startSession(ctx, client, pair)
			client.Close()
			if s != nil {
				s.close()
			}
			if e := <-done; e != nil {
				t.Fatal(e)
			}
			if (err == nil) != (kind == "matching") {
				t.Fatalf("wrong direct-session result: %v", err)
			}
		})
	}
}
