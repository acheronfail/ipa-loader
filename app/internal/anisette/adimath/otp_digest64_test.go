package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestOTPDigest64Native(t *testing.T) {
	b, err := os.ReadFile("testdata/native_otp_digest64.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Input   string `json:"input64_hex"`
			Context OTPDigest64Context
			Output  string `json:"output32_hex"`
		}
	}
	if err = json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	for i, v := range fixture.Vectors {
		var input [64]byte
		raw, err := hex.DecodeString(v.Input)
		if err != nil || len(raw) != 64 {
			t.Fatal("invalid fixture input")
		}
		copy(input[:], raw)
		got := OTPDigest64(input, v.Context)
		if hex.EncodeToString(got[:]) != v.Output {
			t.Errorf("vector %d: got%x want%s", i, got, v.Output)
		}
	}
}
