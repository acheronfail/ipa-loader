package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestOTPExpansionNativeSynthetic(t *testing.T) {
	var f struct {
		Vectors []struct {
			Profile, Input string
			Hash           OTPPrekeyState `json:"hash_state"`
			Expected       [167]uint32
			Tables         OTPTables
		}
	}
	raw, e := os.ReadFile("testdata/native_otp_expansion.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &f); e != nil {
		t.Fatal(e)
	}
	for n, v := range f.Vectors {
		var profile [384]byte
		var input [96]byte
		b, e := hex.DecodeString(v.Profile)
		if e != nil || len(b) != 384 {
			t.Fatalf("invalid profile %d", n)
		}
		copy(profile[:], b)
		b, e = hex.DecodeString(v.Input)
		if e != nil || len(b) != 96 {
			t.Fatalf("invalid message %d", n)
		}
		copy(input[:], b)
		got := otpExpandArithmetic(profile, v.Hash, input)
		if got != v.Expected {
			for i := range got {
				if got[i] != v.Expected[i] {
					t.Fatalf("case %d word %d got%x want%x", n, i, got[i], v.Expected[i])
				}
			}
		}
		ctx, _ := otpContextFromExpansion(got)
		if ctx.Tables != v.Tables {
			t.Fatalf("case %d expanded tables differ", n)
		}
	}
}
