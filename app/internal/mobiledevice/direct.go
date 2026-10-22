//go:build windows || linux || darwin

package mobiledevice

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"howett.net/plist"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// DirectDevice authenticates to an already-paired device through a local VPN.
// It does not establish trust or bypass the pairing handshake.
type DirectDevice struct {
	UDID, Address string
	PairRecord    []byte
}

func (DirectDevice) String() string   { return "Private on-device connection" }
func (DirectDevice) GoString() string { return "Private on-device connection" }

var directRoute struct {
	sync.RWMutex
	device *DirectDevice
}

func ConfigureDirectDevice(d DirectDevice) error {
	ip, err := netip.ParseAddr(d.Address)
	if err != nil || !ip.Is4() || !ip.IsPrivate() || d.UDID == "" || len(d.UDID) > 128 {
		return errors.New("Invalid local VPN device address or identity")
	}
	if _, err = decodePairRecord(d.PairRecord); err != nil {
		return err
	}
	d.PairRecord = append([]byte(nil), d.PairRecord...)
	directRoute.Lock()
	defer directRoute.Unlock()
	directRoute.device = &d
	return nil
}
func currentDirect() *DirectDevice {
	directRoute.RLock()
	defer directRoute.RUnlock()
	return directRoute.device
}
func decodePairRecord(raw []byte) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return nil, errors.New("Invalid pairing record size")
	}
	var pair map[string]any
	if _, err := plist.Unmarshal(raw, &pair); err != nil {
		return nil, errors.New("Invalid pairing record")
	}
	for _, k := range []string{"HostID", "SystemBUID"} {
		if s, _ := pair[k].(string); s == "" {
			return nil, errors.New("Incomplete pairing identity")
		}
	}
	for _, k := range []string{"RootCertificate", "RootPrivateKey", "DeviceCertificate"} {
		if b, _ := pair[k].([]byte); len(b) == 0 {
			return nil, errors.New("Incomplete pairing credentials")
		}
	}
	cert, _ := pair["RootCertificate"].([]byte)
	key, _ := pair["RootPrivateKey"].([]byte)
	if _, err := tls.X509KeyPair(cert, key); err != nil {
		return nil, errors.New("Invalid pairing TLS identity")
	}
	device, _ := pair["DeviceCertificate"].([]byte)
	block, _ := pem.Decode(device)
	if block == nil {
		return nil, errors.New("Invalid paired device certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return nil, errors.New("Invalid paired device certificate")
	}
	return pair, nil
}
func (d *DirectDevice) dial(ctx context.Context, port uint16) (net.Conn, error) {
	c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(d.Address, strconv.Itoa(int(port))))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("Connect LocalDevVPN and Wi-Fi, then try again. Check that its Device IP matches IPA Loader's connection settings")
	}
	return c, nil
}
func (d *DirectDevice) session(ctx context.Context, udid string) (*windowsSession, error) {
	if udid != d.UDID {
		return nil, errors.New("Pairing belongs to another device")
	}
	pair, err := decodePairRecord(d.PairRecord)
	if err != nil {
		return nil, err
	}
	conn, err := d.dial(ctx, 62078)
	if err != nil {
		return nil, err
	}
	return d.startSession(ctx, conn, pair)
}
func (d *DirectDevice) startSession(ctx context.Context, conn net.Conn, pair map[string]any) (*windowsSession, error) {
	s := &windowsSession{conn: conn, pair: pair, device: WindowsDevice{UDID: d.UDID, Transport: "Network"}, dial: d.dial}
	fail := func(err error) (*windowsSession, error) { s.close(); return nil, err }
	r, err := deviceExchange(ctx, conn, map[string]any{"Request": "StartSession", "HostID": pair["HostID"], "SystemBUID": pair["SystemBUID"]})
	if err != nil {
		return fail(errors.New("Pairing was rejected. Unlock the iPhone; if it persists, reinstall IPA Loader using the desktop bootstrap button"))
	}
	s.sessionID, _ = r["SessionID"].(string)
	if s.sessionID == "" {
		return fail(errors.New("Device did not confirm the pairing session"))
	}
	if ssl, _ := r["EnableSessionSSL"].(bool); !ssl {
		return fail(errors.New("Device did not enable authenticated pairing TLS"))
	}
	secure, err := pairedTLS(ctx, conn, pair)
	if err != nil {
		return fail(err)
	}
	s.conn = secure
	r, err = deviceExchange(ctx, s.conn, map[string]any{"Request": "GetValue", "Key": "UniqueDeviceID"})
	if err != nil {
		return fail(err)
	}
	if r["Value"] != d.UDID {
		return fail(errors.New("VPN reached a different device"))
	}
	return s, nil
}
func (d *DirectDevice) devices(ctx context.Context) ([]WindowsDevice, error) {
	s, err := d.session(ctx, d.UDID)
	if err != nil {
		return nil, err
	}
	defer s.close()
	r, err := deviceExchange(ctx, s.conn, map[string]any{"Request": "GetValue"})
	if err != nil {
		return nil, err
	}
	v, _ := r["Value"].(map[string]any)
	name, _ := v["DeviceName"].(string)
	model, _ := v["ProductType"].(string)
	version, _ := v["ProductVersion"].(string)
	return []WindowsDevice{{UDID: d.UDID, Name: name, Model: model, OSVersion: version, Transport: "Network"}}, nil
}

// ExportPairRecord verifies an existing trusted session before exporting secrets.
// This is only used by an explicit desktop bootstrap operation.
func ExportPairRecord(ctx context.Context, udid string) ([]byte, error) {
	s, err := windowsPairedSession(ctx, udid)
	if err != nil {
		return nil, err
	}
	defer s.close()
	raw, err := plist.Marshal(s.pair, plist.XMLFormat)
	if err != nil {
		return nil, errors.New("Could not encode bootstrap pairing")
	}
	if _, err = decodePairRecord(raw); err != nil {
		clear(raw)
		return nil, err
	}
	return raw, nil
}
