package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestOTPPrekeyNativeSynthetic(t *testing.T) {
	b, e := os.ReadFile("testdata/native_otp_prekey.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Vectors []struct {
			Input string `json:"input32_hex"`
			Steps []struct {
				Input  byte
				Before OTPPrekeyState `json:"state_before"`
				After  OTPPrekeyState `json:"state_after"`
			}
		}
	}
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	for n, v := range f.Vectors {
		a, e := hex.DecodeString(v.Input)
		if e != nil || len(a) != 32 {
			t.Fatal("invalidfixture")
		}
		var key [32]byte
		copy(key[:], a)
		for i, s := range v.Steps {
			got := otpPrekeyStep(s.Before, s.Input, uint32(i))
			if got != s.After {
				t.Fatalf("vector%d step%d got%x want%x", n, i, got, s.After)
			}
		}
		got := HashOTPPrekey32(key)
		if got != v.Steps[31].After {
			t.Fatalf("vector%d final got%x want%x", n, got, v.Steps[31].After)
		}
	}
}
