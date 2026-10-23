package mobiledevice

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"howett.net/plist"
)

// Installation proxy uses length-prefixed property lists. Own the receive
// loop here instead of blocking inside instproxy_upgrade: bounded native reads
// let cancellation stop observation even while iOS waits for an app to close.
// Closing observation never promises rollback of a submitted installation.
type installService interface {
	send([]byte) (int, error)
	receive([]byte, uint32) (int, error)
	close()
}

var errReceiveTimeout = errors.New("device receive poll timed out")

var installCodePattern = regexp.MustCompile(`(?i)\b0xe800[0-9a-f]{4}\b`)

// InstallationRejectionError is a terminal device rejection. Its public message
// is redacted; the full response is available only for private diagnostics.
type InstallationRejectionError struct {
	response map[string]any
}

func (e *InstallationRejectionError) Error() string    { return installationRejectionReason(e.response) }
func (e *InstallationRejectionError) GoString() string { return e.Error() }

func (e *InstallationRejectionError) WriteDiagnostics(w io.Writer) error {
	response := e.response
	if response == nil {
		response = map[string]any{}
	}
	return plist.NewEncoder(w).Encode(response)
}

// Keep diagnostics useful without displaying device paths, account names or
// arbitrary ErrorDescription text. Only known status names and numeric codes
// cross the device-response boundary.
func installationRejection(message map[string]any) error {
	return &InstallationRejectionError{response: message}
}

func installationRejectionReason(message map[string]any) string {
	reason := "The iPhone rejected this IPA"
	switch message["Error"] {
	case "ApplicationVerificationFailed":
		reason = "The iPhone could not verify the app signature or provisioning profile"
	case "BundleVerificationFailed":
		reason = "The iPhone could not verify an app bundle"
	case "PackageInspectionFailed":
		reason = "The iPhone could not inspect the IPA package"
	case "PackageExtractionFailed":
		reason = "The iPhone could not extract the IPA package"
	case "InsufficientStorage":
		reason = "The iPhone does not have enough free storage to install this app"
	case "DeviceOSVersionTooLow":
		reason = "This app requires a newer iOS version"
	case "MaximumNumberOfAppsForFreeAccount":
		reason = "The iPhone has reached its free-account app limit"
	case "ApplicationSignatureInvalid":
		reason = "The iPhone rejected the app signature"
	case "InstallProhibited":
		reason = "App installation is restricted on this iPhone"
	}
	if description, ok := message["ErrorDescription"].(string); ok {
		lowerDescription := strings.ToLower(description)
		// Installation coordination can wrap ENOSPC in APIInternalError rather
		// than the dedicated InsufficientStorage error. Match fixed phrases only;
		// the description also contains private device paths and identifiers.
		if strings.Contains(lowerDescription, "no space left on device") || strings.Contains(lowerDescription, "there isn’t enough space") || strings.Contains(lowerDescription, "there isn't enough space") {
			reason = "The iPhone does not have enough free storage to install this app. Free space in Settings > General > iPhone Storage, then retry"
		}
		// iOS sometimes wraps the free-account app limit in ApplicationVerificationFailed.
		// Recognize it without exposing the installed-app identifiers in the description.
		if strings.Contains(lowerDescription, "maximum number of installed apps using a free developer profile") {
			reason = "The iPhone has reached its three-app free-account limit. Free a developer-app slot, then retry"
		}
		if code := installCodePattern.FindString(description); code != "" {
			reason += " (" + code + ")"
		}
	}
	if code, ok := message["ErrorDetail"].(uint64); ok && code != 0 {
		reason += fmt.Sprintf(" (device error %d)", code)
	}
	return reason
}

func receiveExact(ctx context.Context, service installService, buffer []byte) error {
	for offset := 0; offset < len(buffer); {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := service.receive(buffer[offset:], 250)
		if n < 0 || n > len(buffer)-offset {
			return errors.New("Invalid installation response byte count")
		}
		offset += n
		if n == 0 && err == nil {
			return io.ErrUnexpectedEOF
		}
		if err != nil && !errors.Is(err, errReceiveTimeout) {
			return err
		}
	}
	return ctx.Err()
}

func runUpgrade(ctx context.Context, service installService, path string, callbacks ...func(InstallProgress)) (submitted bool, err error) {
	defer service.close()
	// Match AltServer's development install source. iOS rejects free-account
	// profiles when the request omits this option and defaults to a user install.
	body, err := plist.Marshal(map[string]any{"Command": "Upgrade", "PackagePath": path, "ClientOptions": map[string]any{"PackageType": "Developer"}}, plist.XMLFormat)
	if err != nil {
		return false, errors.New("Could not encode installation request")
	}
	packet := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(packet, uint32(len(body)))
	copy(packet[4:], body)
	for offset := 0; offset < len(packet); {
		if err = ctx.Err(); err != nil {
			return
		}
		var n int
		n, err = service.send(packet[offset:])
		if n < 0 || n > len(packet)-offset {
			return submitted, errors.New("Invalid installation request byte count")
		}
		if n > 0 {
			submitted = true
			offset += n
		}
		if err != nil {
			return
		}
		if n == 0 {
			return submitted, io.ErrNoProgress
		}
	}
	notify := func(percent int) {
		for _, callback := range callbacks {
			if callback != nil {
				callback(InstallProgress{Submitted: submitted, Percent: percent})
			}
		}
	}
	notify(-1)
	for {
		var prefix [4]byte
		if err = receiveExact(ctx, service, prefix[:]); err != nil {
			return
		}
		size := binary.BigEndian.Uint32(prefix[:])
		if size == 0 || size > 4<<20 {
			return submitted, errors.New("Invalid installation response size")
		}
		response := make([]byte, size)
		if err = receiveExact(ctx, service, response); err != nil {
			return
		}
		var message map[string]any
		if _, err = plist.Unmarshal(response, &message); err != nil || message == nil {
			return submitted, errors.New("Invalid installation response property list")
		}
		// Never surface untrusted ErrorDescription text (which can include device
		// paths and account identifiers) in the user-facing error.
		if value, exists := message["Error"]; exists {
			text, ok := value.(string)
			if !ok {
				return submitted, errors.New("The iPhone returned an invalid installation error")
			}
			if text != "" {
				return submitted, installationRejection(message)
			}
		}
		status, ok := message["Status"].(string)
		if !ok || status == "" {
			return submitted, errors.New("The iPhone returned an incomplete installation status")
		}
		if status == "Complete" {
			notify(100)
			return submitted, nil
		}
		if value, ok := message["PercentComplete"].(uint64); ok && value <= 100 {
			notify(int(value))
		}
	}
}
