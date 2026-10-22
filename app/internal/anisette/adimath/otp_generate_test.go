package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestGenerateAndroidOTPNative(t *testing.T) {
	b, err := os.ReadFile("testdata/native_android_otp_complete.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Key     string `json:"normalized_prekey32_hex"`
			Profile string `json:"profile384_hex"`
			Seconds int64  `json:"unix_seconds"`
			Output  string `json:"otp28_hex"`
		}
	}
	if err = json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	for i, v := range fixture.Vectors {
		var key [32]byte
		var profile [384]byte
		raw, err := hex.DecodeString(v.Key)
		if err != nil || len(raw) != 32 {
			t.Fatal("invalid fixture key")
		}
		copy(key[:], raw)
		raw, err = hex.DecodeString(v.Profile)
		if err != nil || len(raw) != 384 {
			t.Fatal("invalid fixture profile")
		}
		copy(profile[:], raw)
		got := GenerateAndroidOTP(key, profile, v.Seconds)
		if hex.EncodeToString(got[:]) != v.Output {
			t.Errorf("vector%d got%x want%s", i, got, v.Output)
		}
	}
}
