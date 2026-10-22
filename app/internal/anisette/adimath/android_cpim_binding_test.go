package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestAndroidCPIMBindingNative(t *testing.T) {
	b, err := os.ReadFile("testdata/native_android_cpim_binding.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Key    string `json:"normalized_prekey32_hex"`
			Output string `json:"field32_hex"`
		}
	}
	if err = json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	for i, v := range fixture.Vectors {
		var key [32]byte
		raw, err := hex.DecodeString(v.Key)
		if err != nil || len(raw) != 32 {
			t.Fatal("invalid fixture key")
		}
		copy(key[:], raw)
		got := TransformAndroidCPIMField32(key)
		if hex.EncodeToString(got[:]) != v.Output {
			t.Errorf("vector%d got%x want%s", i, got, v.Output)
		}
	}
}
