package mobiledevice

import (
	"howett.net/plist"
	"testing"
)

func TestProvisioningProfilePayload(t *testing.T) {
	// Exercise the actual plist decoder's numeric and data representations.
	raw, err := plist.Marshal(map[string]any{"Status": uint64(0), "Payload": []any{[]byte("profile")}}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	var response map[string]any
	if _, err = plist.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	profiles, err := provisioningProfilePayload(response)
	if err != nil || len(profiles) != 1 || string(profiles[0]) != "profile" {
		t.Fatalf("unexpected payload: %v %v", profiles, err)
	}
	for _, bad := range []map[string]any{
		{}, {"Status": uint64(1), "Payload": []any{}},
		{"Status": uint64(0), "Payload": []any{"not data"}},
		{"Status": uint64(0), "Payload": []any{[]byte{}}},
	} {
		if _, err := provisioningProfilePayload(bad); err == nil {
			t.Fatal("accepted malformed/error profile response")
		}
	}
}

func TestProfileInstallStatusRequiresExplicitSuccess(t *testing.T) {
	if err := provisioningInstallResult(map[string]any{"Status": uint64(0)}); err != nil {
		t.Fatal(err)
	}
	if err := provisioningInstallResult(map[string]any{"Status": uint64(1)}); err != ErrProfileInstallRejected {
		t.Fatal("device rejection was not distinguished from transport failure")
	}
	for _, response := range []map[string]any{{}, {"Status": "0"}, {"Status": true}} {
		if err := provisioningInstallResult(response); err == nil || err == ErrProfileInstallRejected {
			t.Fatal("malformed acknowledgement was trusted")
		}
	}
}
