package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestAndroidDigestEncodingNative(t *testing.T) {
	var f struct {
		Vectors []struct {
			Input  string `json:"input_hex"`
			Output string `json:"output_hex"`
		}
	}
	b, e := os.ReadFile("testdata/native_android_digest_encoding.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	for i, v := range f.Vectors {
		b, e := hex.DecodeString(v.Input)
		if e != nil || len(b) != 16 {
			t.Fatalf("invalid fixture %d", i)
		}
		var input [16]byte
		copy(input[:], b)
		got := EncodeAndroidDigest16(input)
		if hex.EncodeToString(got[:]) != v.Output {
			t.Fatalf("vector %d got%x want%s", i, got, v.Output)
		}
	}
}
