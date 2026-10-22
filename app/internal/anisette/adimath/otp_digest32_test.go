package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestOTPDigest32NativeSynthetic(t *testing.T) {
	var f struct {
		Vectors []struct {
			Input      string `json:"input_hex"`
			Output     string `json:"output_hex"`
			Serialized string `json:"serialized_hex"`
			Context    OTPDigest64Context
		}
	}
	b, e := os.ReadFile("testdata/native_otp_digest32.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	for i, v := range f.Vectors {
		raw, e := hex.DecodeString(v.Input)
		if e != nil || len(raw) != 32 {
			t.Fatalf("invalid fixture %d", i)
		}
		var input [32]byte
		copy(input[:], raw)
		got := OTPDigest32(input)
		if hex.EncodeToString(got.Digest[:]) != v.Output || hex.EncodeToString(got.Serialized[:]) != v.Serialized || got.NextContext != v.Context {
			t.Fatalf("first digest %d differs", i)
		}
	}
}
