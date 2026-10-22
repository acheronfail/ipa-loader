package adimath

import (
	"encoding/json"
	"os"
	"testing"
)

func TestOTPCompressionRoundsNative(t *testing.T) {
	data, err := os.ReadFile("testdata/native_otp_rounds.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Input  OTPCompressionState
			WordA  uint32 `json:"word_a"`
			WordB  uint32 `json:"word_b"`
			Last   bool
			Output OTPCompressionState
		}
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for n, v := range fixture.Vectors {
		got := OTPCompressionRound(v.Input, v.WordA, v.WordB, v.Last)
		for _, i := range []int{0, 1, 2, 3, 4, 5, 6, 7} {
			if got[i] != v.Output[i] {
				t.Fatalf("round%d r%d got%08x want%08x", n, i, got[i], v.Output[i])
			}
		}
	}
}
