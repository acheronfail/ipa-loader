package mobiledevice

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"howett.net/plist"
)

type fakeInstallService struct {
	out, in  bytes.Buffer
	reads    int
	fragment bool
	closed   bool
	cancel   context.CancelFunc
}

func (s *fakeInstallService) send(b []byte) (int, error) {
	n := len(b)
	if n > 7 {
		n = 7
	}
	return s.out.Write(b[:n])
}
func (s *fakeInstallService) receive(b []byte, _ uint32) (int, error) {
	s.reads++
	if s.cancel != nil {
		s.cancel()
		return 0, errReceiveTimeout
	}
	if s.fragment && len(b) > 2 {
		b = b[:2]
	}
	n, err := s.in.Read(b)
	if s.fragment && n > 0 && s.reads%2 == 0 {
		return n, errReceiveTimeout
	}
	return n, err
}
func (s *fakeInstallService) close() { s.closed = true }
func responseFrame(message map[string]any) []byte {
	body, _ := plist.Marshal(message, plist.XMLFormat)
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame, uint32(len(body)))
	copy(frame[4:], body)
	return frame
}

func TestInstallationProtocolFragmentedTimeoutsAndTerminalStatus(t *testing.T) {
	service := &fakeInstallService{fragment: true}
	service.in.Write(responseFrame(map[string]any{"Status": "Installing", "PercentComplete": 95}))
	service.in.Write(responseFrame(map[string]any{"Status": "Complete"}))
	submitted, err := runUpgrade(context.Background(), service, "PublicStaging/owned.ipa")
	if err != nil || !submitted || !service.closed {
		t.Fatal("fragmented complete status was not recognized", err)
	}
	packet := service.out.Bytes()
	if len(packet) < 4 || int(binary.BigEndian.Uint32(packet)) != len(packet)-4 {
		t.Fatal("request framing is not exact")
	}
	var command map[string]any
	if _, err = plist.Unmarshal(packet[4:], &command); err != nil || command["Command"] != "Upgrade" || command["PackagePath"] != "PublicStaging/owned.ipa" {
		t.Fatal("incorrect installation command")
	}
	options, ok := command["ClientOptions"].(map[string]any)
	if !ok || options["PackageType"] != "Developer" {
		t.Fatal("free-account installation must use the development source")
	}
}

func TestInstallationObservationCancellationDoesNotClaimRollback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	service := &fakeInstallService{cancel: cancel}
	submitted, err := runUpgrade(ctx, service, "PublicStaging/owned.ipa")
	if !errors.Is(err, context.Canceled) || !submitted || !service.closed {
		t.Fatal("cancelled observation lost submission state")
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	service = &fakeInstallService{}
	submitted, err = runUpgrade(cancelled, service, "PublicStaging/owned.ipa")
	if !errors.Is(err, context.Canceled) || submitted || service.out.Len() != 0 || !service.closed {
		t.Fatal("pre-cancelled operation sent an installation")
	}
}

func TestIncompleteOrRejectedInstallationIsNeverSuccess(t *testing.T) {
	for _, kind := range []string{"empty frame", "oversized", "truncated", "missing status", "progress only", "error with complete", "invalid plist"} {
		t.Run(kind, func(t *testing.T) {
			service := &fakeInstallService{}
			switch kind {
			case "empty frame":
				service.in.Write(make([]byte, 4))
			case "oversized":
				var prefix [4]byte
				binary.BigEndian.PutUint32(prefix[:], (4<<20)+1)
				service.in.Write(prefix[:])
			case "truncated":
				service.in.Write([]byte{0, 0})
			case "missing status":
				service.in.Write(responseFrame(map[string]any{"PercentComplete": 100}))
			case "progress only":
				service.in.Write(responseFrame(map[string]any{"Status": "Installing", "PercentComplete": 100}))
			case "error with complete":
				service.in.Write(responseFrame(map[string]any{"Status": "Complete", "Error": "ApplicationVerificationFailed", "ErrorDescription": "private@example.invalid"}))
			case "invalid plist":
				service.in.Write([]byte{0, 0, 0, 3, 'b', 'a', 'd'})
			}
			submitted, err := runUpgrade(context.Background(), service, "PublicStaging/owned.ipa")
			if err == nil || !submitted || !service.closed || strings.Contains(err.Error(), "private@example.invalid") {
				t.Fatal("invalid result reported success or leaked private text")
			}
		})
	}
}

func TestReceiveClosedConnectionDoesNotSpin(t *testing.T) {
	service := &zeroInstallService{}
	if err := receiveExact(context.Background(), service, make([]byte, 4)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("closed receive loop did not stop")
	}
}

func TestInstallationRejectionRedactsDeviceText(t *testing.T) {
	err := installationRejection(map[string]any{"Error": "ApplicationVerificationFailed", "ErrorDescription": "private@example.invalid /private/path 0xe8008015", "ErrorDetail": uint64(42)})
	if !strings.Contains(err.Error(), "0xe8008015") || !strings.Contains(err.Error(), "device error 42") || strings.Contains(err.Error(), "private") {
		t.Fatal("diagnostic code missing or private text leaked")
	}
	err = installationRejection(map[string]any{"Error": "private@example.invalid", "ErrorDescription": "private/path"})
	if strings.Contains(err.Error(), "private") {
		t.Fatal("unknown error leaked")
	}
}

func TestInstallationRejectionRetainsPrivateDiagnostics(t *testing.T) {
	message := map[string]any{"Error": "PackageExtractionFailed", "ErrorDescription": "private@example.invalid /private/device/path"}
	err := installationRejection(message)
	var rejection *InstallationRejectionError
	if !errors.As(err, &rejection) || !strings.Contains(err.Error(), "extract") {
		t.Fatal("device rejection lost its type or useful message")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", err, err), "private") {
		t.Fatal("private response leaked through error formatting")
	}
	var diagnostic bytes.Buffer
	if err := rejection.WriteDiagnostics(&diagnostic); err != nil {
		t.Fatal(err)
	}
	var response map[string]any
	if _, err := plist.Unmarshal(diagnostic.Bytes(), &response); err != nil || response["ErrorDescription"] != message["ErrorDescription"] || response["Error"] != message["Error"] {
		t.Fatal("private diagnostics lost the device rejection", err)
	}
}

func TestWrappedStorageRejectionHasActionablePrivateMessage(t *testing.T) {
	for _, description := range []string{
		"copyfile of /private/device/path failed: No space left on device",
		"This app can’t be installed because there isn’t enough space. private@example.invalid",
		"This app can't be installed because there isn't enough space. /private/path",
	} {
		err := installationRejection(map[string]any{"Error": "APIInternalError", "ErrorDescription": description})
		if !strings.Contains(err.Error(), "iPhone Storage") || strings.Contains(err.Error(), "private") {
			t.Fatal("lost storage guidance or exposed private device text")
		}
	}
}

type zeroInstallService struct{}

func (*zeroInstallService) send([]byte) (int, error)            { return 0, nil }
func (*zeroInstallService) receive([]byte, uint32) (int, error) { return 0, nil }
func (*zeroInstallService) close()                              {}

func TestWrappedFreeAccountLimitHasActionablePrivateMessage(t *testing.T) {
	err := installationRejection(map[string]any{"Error": "ApplicationVerificationFailed", "ErrorDescription": "This device has reached the maximum number of installed apps using a free developer profile: private.installed.app"})
	if !strings.Contains(err.Error(), "three-app") || strings.Contains(err.Error(), "private.installed.app") {
		t.Fatal("lost quota guidance or exposed private installed-app identifiers")
	}
}
