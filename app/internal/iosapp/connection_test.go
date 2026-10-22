package iosapp

import (
	"strings"
	"testing"
)

func TestConnectionFailureGuidanceMatchesPayload(t *testing.T) {
	for _, builtin := range []bool{false, true} {
		for _, checking := range []bool{false, true} {
			message := connectionFailureMessage(builtin, checking)
			if builtin {
				if !strings.Contains(message, "Enable Local VPN in Settings") || strings.Contains(message, "LocalDevVPN") || strings.Contains(message, "Device IP") {
					t.Fatalf("built-in VPN guidance is misleading: %s", message)
				}
			} else {
				for _, required := range []string{"Connect LocalDevVPN", "Wi-Fi", "Connection Settings", "Device IP"} {
					if !strings.Contains(message, required) {
						t.Fatalf("LocalDevVPN guidance missing %q: %s", required, message)
					}
				}
				if strings.Contains(message, "Local VPN") {
					t.Fatalf("external VPN guidance mentions built-in controls: %s", message)
				}
			}
			if checking != strings.Contains(message, "Showing saved dates") || checking != strings.Contains(message, "Pull down to retry") {
				t.Fatalf("inventory fallback guidance does not match operation: %s", message)
			}
		}
	}
}
