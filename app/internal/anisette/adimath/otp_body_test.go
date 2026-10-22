package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestOTPBodyNativeSynthetic(t *testing.T) {
	var fixture struct {
		Vectors []struct {
			Context struct {
				State         [4]uint32
				RoundWords    [48]uint32 `json:"round_words"`
				EncodingWords [7]uint64  `json:"encoding_words"`
				Tables        OTPTables
			}
			Input    string `json:"input_hex"`
			Expected string `json:"expected_hex"`
		}
	}
	raw, e := os.ReadFile("testdata/native_otp_body.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &fixture); e != nil {
		t.Fatal(e)
	}
	for i, v := range fixture.Vectors {
		ctx := OTPBodyContext{Tables: v.Context.Tables, State: v.Context.State, RoundWords: v.Context.RoundWords, EncodingWords: v.Context.EncodingWords}
		b, e := hex.DecodeString(v.Input)
		if e != nil || len(b) != 96 {
			t.Fatalf("invalid input %d", i)
		}
		var input [96]byte
		copy(input[:], b)
		got := ComputeOTPBody(&ctx, input)
		if hex.EncodeToString(got[:]) != v.Expected {
			t.Fatalf("vector %d got %x want %s", i, got, v.Expected)
		}
	}
}
