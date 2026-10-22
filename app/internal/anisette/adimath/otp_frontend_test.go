package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestOTPClockNative(t *testing.T) {
	b, err := os.ReadFile("testdata/native_otp_clock.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Seconds int64 `json:"unix_seconds"`
			Counter uint32
			Biased  uint32 `json:"native_biased_word"`
		}
	}
	if err = json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, v := range fixture.Vectors {
		got := OTPCounter(v.Seconds)
		if got != v.Counter || got+0x18e3f2bc != v.Biased {
			t.Errorf("seconds %d: got %x want %x", v.Seconds, got, v.Counter)
		}
	}
}
func TestOTPPreparationMasksNative(t *testing.T) {
	b, err := os.ReadFile("testdata/native_otp_frontend_masks.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Key   string `json:"normalized32_hex"`
			Masks string `json:"masks16_hex"`
		}
	}
	if err = json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, v := range fixture.Vectors {
		var key [32]byte
		raw, err := hex.DecodeString(v.Key)
		if err != nil || len(raw) != len(key) {
			t.Fatal("invalid fixture key")
		}
		copy(key[:], raw)
		got := OTPPreparationMasks(key)
		if hex.EncodeToString(got[:]) != v.Masks {
			t.Fatalf("got %x want %s", got, v.Masks)
		}
	}
}
