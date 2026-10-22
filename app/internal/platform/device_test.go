package platform

import "testing"

func TestDeviceLabelsPreserveRoutingAndDisplayHardwareID(t *testing.T) {
	d := Device{ID: "selected-device", UDID: "hardware-udid", Name: "Test iPhone", Transport: "USB"}
	if d.Label() != "Test iPhone @USB · hardware-udid" {
		t.Fatal(d.Label())
	}
	d.Transport = "WiFi"
	if d.Label() != "Test iPhone @WiFi · hardware-udid" {
		t.Fatal(d.Label())
	}
	d.UDID = ""
	if d.DisplayID() != d.ID {
		t.Fatal("missing UDID should use device ID")
	}
}
