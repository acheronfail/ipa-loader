package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestOTPDigestNativeSynthetic(t *testing.T) {
	b, e := os.ReadFile("testdata/native_otp_digest.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Vectors []struct {
			Input   string `json:"input55_hex"`
			Output  string `json:"output32_hex"`
			Context OTPDigestContext
		}
	}
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	for i, v := range f.Vectors {
		a, e := hex.DecodeString(v.Input)
		if e != nil || len(a) != 55 {
			t.Fatalf("invalidfixture%d", i)
		}
		var m [55]byte
		copy(m[:], a)
		if v.Context != NativeOTPDigestContext() {
			t.Fatal("native fixture differs from immutable digest constants")
		}
		got := OTPDigest55(m, NativeOTPDigestContext())
		if hex.EncodeToString(got[:]) != v.Output {
			t.Fatalf("vector%d got%x want%s", i, got, v.Output)
		}
	}
}
