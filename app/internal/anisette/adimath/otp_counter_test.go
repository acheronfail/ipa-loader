package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestOTPCounterNative(t *testing.T) {
	b, e := os.ReadFile("testdata/native_otp_counter.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Vectors []struct {
			Counter uint32
			Encoded string `json:"encoded8_hex"`
		}
	}
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	for _, v := range f.Vectors {
		got := EncodeOTPCounter8(v.Counter)
		if hex.EncodeToString(got[:]) != v.Encoded {
			t.Errorf("counter%x got%x want%s", v.Counter, got, v.Encoded)
		}
	}
}
