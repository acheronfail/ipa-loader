package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestPrepareOTP55NativeSynthetic(t *testing.T) {
	b, e := os.ReadFile("testdata/native_otp_prepare.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Vectors []struct {
			Counter uint32
			Masks   [16]byte
			Output  string `json:"output55_hex"`
			Steps   []struct {
				Index           int
				Old, New, State byte
			}
		}
	}
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	for n, v := range f.Vectors {
		got := PrepareOTP55(v.Counter, v.Masks)
		if hex.EncodeToString(got[:]) != v.Output {
			t.Fatalf("vector%d got%x want%s", n, got, v.Output)
		}
		var decoded [55]byte
		for i, x := range EncodeOTPCounter8(v.Counter) {
			decoded[i] = x ^ 0x3c
		}
		state := byte(0xf9)
		for i, s := range v.Steps {
			j := (i + 7) % 55
			if s.Index != j || s.Old != decoded[j]^0x3c || s.State != state {
				t.Fatalf("vector%d native step%d input mismatch", n, i)
			}
			decoded[j] ^= v.Masks[i%16] + (state ^ 0x6a)
			if s.New != decoded[j]^0x3c {
				t.Fatalf("vector%d native step%d output mismatch", n, i)
			}
			state ^= 68 * decoded[j]
		}
	}
}
