//go:build linux || darwin

package main

import (
	"ipa-loader/app/internal/platform"
	"testing"
)

func TestFixtureAcceptanceRouteSelection(t *testing.T) {
	usb := platform.Device{ID: "usb-route", Name: "Test iPhone", Transport: "USB"}
	wifi := platform.Device{ID: "wifi-route", Name: "Test iPhone", Transport: "WiFi"}
	for _, tc := range []struct {
		name, transport, want string
		devices               []platform.Device
	}{
		{"explicit wifi", "wifi", "wifi-route", []platform.Device{usb, wifi}},
		{"explicit usb", "usb", "usb-route", []platform.Device{wifi, usb}},
		{"wifi cannot use usb", "wifi", "", []platform.Device{usb}},
		{"usb cannot use wifi", "usb", "", []platform.Device{wifi}},
		{"ambiguous wifi", "wifi", "", []platform.Device{wifi, wifi}},
		{"invalid transport", "auto", "", []platform.Device{usb, wifi}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectFixtureDevice(tc.devices, "Test iPhone", tc.transport)
			if tc.want == "" {
				if err == nil {
					t.Fatal("accepted unavailable/ambiguous route")
				}
				return
			}
			if err != nil || got.ID != tc.want {
				t.Fatal(got.ID, err)
			}
		})
	}
}
