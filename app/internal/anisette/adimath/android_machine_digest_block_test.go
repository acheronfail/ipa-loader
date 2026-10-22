package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestAndroidMachineDigestBackendNative(t *testing.T) {
	b, err := os.ReadFile("testdata/native_android_machine_backend.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Encoded string `json:"encoded16_hex"`
			Output  string `json:"raw_body16_hex"`
		}
	}
	if err = json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	for i, v := range fixture.Vectors {
		var encoded [16]byte
		raw, err := hex.DecodeString(v.Encoded)
		if err != nil || len(raw) != 16 {
			t.Fatal("invalid fixture input")
		}
		copy(encoded[:], raw)
		got := TransformAndroidMachineDigestBlock(encoded)
		if hex.EncodeToString(got[:]) != v.Output {
			t.Errorf("vector%d got%x want%s", i, got, v.Output)
		}
	}
}
