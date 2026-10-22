package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestOTPProfile384NativeSynthetic(t *testing.T) {
	b, e := os.ReadFile("testdata/native_otp_profile.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Vectors []struct {
			Input  string `json:"input384_hex"`
			Output string `json:"output384_hex"`
		}
	}
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	for i, v := range f.Vectors {
		a, e := hex.DecodeString(v.Input)
		if e != nil || len(a) != 384 {
			t.Fatal("invalidfixture")
		}
		var input [384]byte
		copy(input[:], a)
		got := DecodeOTPProfile384(input)
		if hex.EncodeToString(got[:]) != v.Output {
			t.Fatalf("vector%d native profile mismatch", i)
		}
	}
}
