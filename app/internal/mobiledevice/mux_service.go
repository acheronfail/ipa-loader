//go:build windows || linux || darwin

package mobiledevice

// This client speaks the public usbmuxd and lockdownd property-list protocols
// to a local device service. It never creates pairing records.
// Protocol references: libusbmuxd/src/libusbmuxd.c and
// libimobiledevice/src/{lockdown,installation_proxy}.c. No upstream code copied.
import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"time"

	"howett.net/plist"
)

type WindowsDevice struct {
	ID                                      uint64
	UDID, Name, Model, OSVersion, Transport string
}

func (WindowsDevice) String() string   { return "Private Windows iPhone identity" }
func (WindowsDevice) GoString() string { return "Private Windows iPhone identity" }

// WindowsDevices enumerates iPhones on Apple's reported USB and Network routes
// and reads basic lockdown identity. Transport selection remains explicit.
func WindowsDevices(ctx context.Context) ([]WindowsDevice, error) {
	if direct := currentDirect(); direct != nil {
		return direct.devices(ctx)
	}
	records, err := muxDevices(ctx)
	if err != nil {
		return nil, err
	}
	var result []WindowsDevice
	for _, record := range records {
		if record.Transport != "USB" && record.Transport != "Network" {
			continue
		}
		conn, err := muxConnect(ctx, record.ID, 62078)
		if err != nil {
			return nil, err
		}
		response, err := deviceExchange(ctx, conn, map[string]any{"Request": "GetValue"})
		conn.Close()
		if err != nil {
			return nil, err
		}
		value, _ := response["Value"].(map[string]any)
		model, _ := value["ProductType"].(string)
		if len(model) < 6 || model[:6] != "iPhone" {
			continue
		}
		record.Name, _ = value["DeviceName"].(string)
		record.Model = model
		record.OSVersion, _ = value["ProductVersion"].(string)
		if record.Name == "" {
			record.Name = "iPhone"
		}
		result = append(result, record)
	}
	return result, nil
}

func muxDevices(ctx context.Context) ([]WindowsDevice, error) {
	response, err := muxControl(ctx, map[string]any{"MessageType": "ListDevices"})
	if err != nil {
		return nil, err
	}
	list, ok := response["DeviceList"].([]any)
	if !ok {
		return nil, errors.New("Apple Mobile Device Service returned an invalid device list")
	}
	var devices []WindowsDevice
	for _, item := range list {
		record, _ := item.(map[string]any)
		props, _ := record["Properties"].(map[string]any)
		udid, _ := props["SerialNumber"].(string)
		transport, _ := props["ConnectionType"].(string)
		id, ok := record["DeviceID"].(uint64)
		if !ok || id == 0 || udid == "" || len(udid) > 128 {
			return nil, errors.New("Apple Mobile Device Service returned an invalid device identity")
		}
		devices = append(devices, WindowsDevice{ID: id, UDID: udid, Transport: transport})
	}
	return devices, nil
}

func muxControl(ctx context.Context, request map[string]any) (map[string]any, error) {
	conn, err := muxSocket(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return muxExchange(ctx, conn, request)
}

func muxExchange(ctx context.Context, conn net.Conn, request map[string]any) (map[string]any, error) {
	request["ClientVersionString"] = "IPA Loader"
	request["ProgName"] = "IPA Loader"
	request["kLibUSBMuxVersion"] = uint64(3)
	body, err := plist.Marshal(request, plist.XMLFormat)
	if err != nil {
		return nil, errors.New("Could not encode Apple device request")
	}
	packet := make([]byte, 16+len(body))
	binary.LittleEndian.PutUint32(packet, uint32(len(packet)))
	binary.LittleEndian.PutUint32(packet[4:], 1)
	binary.LittleEndian.PutUint32(packet[8:], 8)
	binary.LittleEndian.PutUint32(packet[12:], 1)
	copy(packet[16:], body)
	stop := watchConnection(ctx, conn)
	defer stop()
	if err = writeAll(conn, packet); err != nil {
		return nil, deviceIOError(ctx)
	}
	var header [16]byte
	if _, err = io.ReadFull(conn, header[:]); err != nil {
		return nil, deviceIOError(ctx)
	}
	size := binary.LittleEndian.Uint32(header[:])
	if size <= 16 || size > 4<<20 || binary.LittleEndian.Uint32(header[4:]) != 1 || binary.LittleEndian.Uint32(header[8:]) != 8 || binary.LittleEndian.Uint32(header[12:]) != 1 {
		return nil, errors.New("Invalid Apple Mobile Device Service response")
	}
	data := make([]byte, int(size)-16)
	if _, err = io.ReadFull(conn, data); err != nil {
		return nil, deviceIOError(ctx)
	}
	var response map[string]any
	if _, err = plist.Unmarshal(data, &response); err != nil || response == nil {
		return nil, errors.New("Invalid Apple Mobile Device Service response")
	}
	if code, ok := response["Number"].(uint64); ok && code != 0 {
		return nil, errors.New("The local device service rejected the request; unlock the iPhone and establish trust with the system device pairing tool")
	}
	return response, nil
}

func muxConnect(ctx context.Context, id uint64, port uint16) (net.Conn, error) {
	conn, err := muxSocket(ctx)
	if err != nil {
		return nil, err
	}
	_, err = muxExchange(ctx, conn, map[string]any{"MessageType": "Connect", "DeviceID": id, "PortNumber": uint64(port>>8 | port<<8)})
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func writeAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
		data = data[n:]
	}
	return nil
}

func watchConnection(ctx context.Context, conn net.Conn) func() {
	// Deadline bounds an individual protocol operation. AfterFunc gives immediate
	// cancellation even while a USB read is blocked; stopping waits for its callback.
	deadline := time.Now().Add(15 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()); close(done) })
	return func() {
		if !stop() {
			<-done
		}
		_ = conn.SetDeadline(time.Time{})
	}
}
func deviceIOError(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.New("Could not read from the iPhone; reconnect and unlock it, then try again")
}

func deviceExchange(ctx context.Context, conn net.Conn, request map[string]any) (map[string]any, error) {
	request["Label"] = "IPA Loader"
	stop := watchConnection(ctx, conn)
	defer stop()
	if err := sendDevicePlist(conn, request); err != nil {
		return nil, deviceIOError(ctx)
	}
	response, err := readDevicePlist(conn)
	if err != nil {
		return nil, deviceIOError(ctx)
	}
	if _, ok := response["Error"]; ok {
		return nil, errors.New("The iPhone rejected the request; unlock it and confirm this computer is trusted")
	}
	return response, nil
}
func sendDevicePlist(conn net.Conn, request map[string]any) error {
	body, err := plist.Marshal(request, plist.XMLFormat)
	if err != nil {
		return err
	}
	packet := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(packet, uint32(len(body)))
	copy(packet[4:], body)
	return writeAll(conn, packet)
}
func readDevicePlist(conn net.Conn) (map[string]any, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > 8<<20 {
		return nil, errors.New("Invalid device response size")
	}
	data := make([]byte, int(size))
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}
	var response map[string]any
	if _, err := plist.Unmarshal(data, &response); err != nil || response == nil {
		return nil, errors.New("Invalid device response")
	}
	return response, nil
}

type windowsSession struct {
	conn      net.Conn
	device    WindowsDevice
	pair      map[string]any
	sessionID string
	dial      func(context.Context, uint16) (net.Conn, error)
}

func (s *windowsSession) close() { s.conn.Close(); clear(s.pair) }

func windowsPairedSession(ctx context.Context, udid string) (*windowsSession, error) {
	return windowsSessionForTransport(ctx, udid, "")
}
func windowsSessionForTransport(ctx context.Context, udid, transport string) (*windowsSession, error) {
	if direct := currentDirect(); direct != nil {
		return direct.session(ctx, udid)
	}
	devices, err := muxDevices(ctx)
	if err != nil {
		return nil, err
	}
	var selected *WindowsDevice
	for i := range devices {
		if devices[i].UDID == udid && (devices[i].Transport == "USB" || devices[i].Transport == "Network") && (transport == "" || transport == "usb" && devices[i].Transport == "USB" || transport == "wifi" && devices[i].Transport == "Network") {
			selected = &devices[i]
			break
		}
	}
	if selected == nil {
		return nil, errors.New("Selected iPhone is disconnected")
	}
	response, err := muxControl(ctx, map[string]any{"MessageType": "ReadPairRecord", "PairRecordID": udid})
	if err != nil {
		return nil, err
	}
	raw, ok := response["PairRecordData"].([]byte)
	if !ok || len(raw) == 0 || len(raw) > 1<<20 {
		return nil, errors.New("This computer has no usable pairing record; unlock the iPhone and establish trust with the system device pairing tool")
	}
	var pair map[string]any
	if _, err = plist.Unmarshal(raw, &pair); err != nil {
		return nil, errors.New("Existing iPhone pairing record is invalid")
	}
	clear(raw)
	conn, err := muxConnect(ctx, selected.ID, 62078)
	if err != nil {
		return nil, err
	}
	s := &windowsSession{conn: conn, device: *selected, pair: pair}
	fail := func(err error) (*windowsSession, error) { s.close(); return nil, err }
	host, _ := pair["HostID"].(string)
	buid, _ := pair["SystemBUID"].(string)
	if host == "" {
		return fail(errors.New("Existing iPhone pairing record is incomplete"))
	}
	if buid == "" {
		r, e := muxControl(ctx, map[string]any{"MessageType": "ReadBUID"})
		if e != nil {
			return fail(e)
		}
		buid, _ = r["BUID"].(string)
	}
	if buid == "" {
		return fail(errors.New("Apple Mobile Device Service did not provide its host identity"))
	}
	pair["SystemBUID"] = buid
	response, err = deviceExchange(ctx, conn, map[string]any{"Request": "StartSession", "HostID": host, "SystemBUID": buid})
	if err != nil {
		return fail(err)
	}
	s.sessionID, _ = response["SessionID"].(string)
	if s.sessionID == "" {
		return fail(errors.New("The iPhone did not start a paired session"))
	}
	if ssl, _ := response["EnableSessionSSL"].(bool); ssl {
		secure, e := pairedTLS(ctx, conn, pair)
		if e != nil {
			return fail(e)
		}
		s.conn = secure
	}
	return s, nil
}
func pairedTLS(ctx context.Context, conn net.Conn, pair map[string]any) (net.Conn, error) {
	cert, _ := pair["RootCertificate"].([]byte)
	key, _ := pair["RootPrivateKey"].([]byte)
	identity, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, errors.New("Existing pairing TLS identity is invalid")
	}
	deviceCert, _ := pair["DeviceCertificate"].([]byte)
	block, _ := pem.Decode(deviceCert)
	if block == nil {
		return nil, errors.New("Existing paired device certificate is invalid")
	}
	expected, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("Existing paired device certificate is invalid")
	}
	config := &tls.Config{Certificates: []tls.Certificate{identity}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, InsecureSkipVerify: true, // The pairing record pins the device public key below; no public CA is used.
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("Missing paired device certificate")
			}
			actual, err := x509.ParseCertificate(rawCerts[0])
			if err != nil || !bytes.Equal(actual.RawSubjectPublicKeyInfo, expected.RawSubjectPublicKeyInfo) {
				return errors.New("Paired device TLS identity mismatch")
			}
			return nil
		}}
	secure := tls.Client(conn, config)
	stop := watchConnection(ctx, conn)
	defer stop()
	if err = secure.HandshakeContext(ctx); err != nil {
		return nil, errors.New("Could not authenticate the existing iPhone pairing session")
	}
	return secure, nil
}

// WindowsLocked checks the actual paired device's PasswordProtected property.
// Unknown state is an error, never interpreted as unlocked.
func WindowsLocked(ctx context.Context, udid string) (bool, error) {
	s, err := windowsPairedSession(ctx, udid)
	if err != nil {
		return false, err
	}
	defer s.close()
	r, err := deviceExchange(ctx, s.conn, map[string]any{"Request": "GetValue", "Key": "PasswordProtected"})
	if err != nil {
		return false, err
	}
	locked, ok := r["Value"].(bool)
	if !ok {
		return false, errors.New("The iPhone did not provide its lock state")
	}
	return locked, nil
}

func (s *windowsSession) service(ctx context.Context, name string) (net.Conn, error) {
	r, err := deviceExchange(ctx, s.conn, map[string]any{"Request": "StartService", "Service": name})
	if err != nil {
		return nil, err
	}
	port, ok := r["Port"].(uint64)
	if !ok || port == 0 || port > 65535 {
		return nil, errors.New("The iPhone did not provide a service port")
	}
	dial := s.dial
	if dial == nil {
		dial = func(ctx context.Context, port uint16) (net.Conn, error) { return muxConnect(ctx, s.device.ID, port) }
	}
	conn, err := dial(ctx, uint16(port))
	if err != nil {
		return nil, err
	}
	if ssl, _ := r["EnableServiceSSL"].(bool); ssl {
		secure, e := pairedTLS(ctx, conn, s.pair)
		if e != nil {
			conn.Close()
			return nil, e
		}
		conn = secure
	}
	return conn, nil
}

// WindowsInstalledApps reads an independent installation-proxy inventory. Its
// values are private; callers should retain only the exact app/version needed.
func WindowsInstalledApps(ctx context.Context, udid string) ([]map[string]any, error) {
	s, err := windowsPairedSession(ctx, udid)
	if err != nil {
		return nil, err
	}
	defer s.close()
	conn, err := s.service(ctx, "com.apple.mobile.installation_proxy")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := watchConnection(ctx, conn)
	defer stop()
	if err = sendDevicePlist(conn, map[string]any{"Command": "Browse", "ClientOptions": map[string]any{"ApplicationType": "User", "ReturnAttributes": []string{"CFBundleIdentifier", "CFBundleShortVersionString", "CFBundleVersion", "CFBundleDisplayName", "ApplicationIdentifier", "Entitlements"}}}); err != nil {
		return nil, deviceIOError(ctx)
	}
	var apps []map[string]any
	for pages := 0; pages < 4096; pages++ {
		response, e := readDevicePlist(conn)
		if e != nil {
			return nil, deviceIOError(ctx)
		}
		if _, ok := response["Error"]; ok {
			return nil, errors.New("The iPhone could not provide installed applications")
		}
		if list, ok := response["CurrentList"].([]any); ok {
			for _, item := range list {
				app, ok := item.(map[string]any)
				if !ok || len(apps) >= 10000 {
					return nil, errors.New("Invalid installed application inventory")
				}
				apps = append(apps, app)
			}
		}
		if status, _ := response["Status"].(string); status == "Complete" {
			return apps, nil
		}
	}
	return nil, errors.New("Installed application inventory exceeded its response limit")
}

// WindowsProvisioningProfiles reads installed profiles without changing them.
func WindowsProvisioningProfiles(ctx context.Context, udid string) ([][]byte, error) {
	s, err := windowsPairedSession(ctx, udid)
	if err != nil {
		return nil, err
	}
	defer s.close()
	conn, err := s.service(ctx, "com.apple.misagent")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := watchConnection(ctx, conn)
	defer stop()
	if err = sendDevicePlist(conn, map[string]any{"MessageType": "CopyAll", "ProfileType": "Provisioning"}); err != nil {
		return nil, deviceIOError(ctx)
	}
	response, err := readDevicePlist(conn)
	if err != nil {
		return nil, deviceIOError(ctx)
	}
	return provisioningProfilePayload(response)
}

// WindowsInstallProvisioningProfile installs one profile without removing any
// existing profiles. Callers must read back the profile store to confirm success.
// Wire format: libimobiledevice src/misagent.c, misagent_install.
func WindowsInstallProvisioningProfile(ctx context.Context, udid string, profile []byte) error {
	if len(profile) == 0 || len(profile) > 16<<20 {
		return errors.New("Invalid provisioning profile size")
	}
	s, err := windowsPairedSession(ctx, udid)
	if err != nil {
		return err
	}
	defer s.close()
	conn, err := s.service(ctx, "com.apple.misagent")
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := watchConnection(ctx, conn)
	defer stop()
	if err = sendDevicePlist(conn, map[string]any{"MessageType": "Install", "ProfileType": "Provisioning", "Profile": profile}); err != nil {
		return deviceIOError(ctx)
	}
	response, err := readDevicePlist(conn)
	if err != nil {
		return deviceIOError(ctx)
	}
	return provisioningInstallResult(response)
}
