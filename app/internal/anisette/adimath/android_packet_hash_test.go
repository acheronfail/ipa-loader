package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestADIPacketChecksumNative(t *testing.T) {
	var f struct {
		Vectors []struct {
			Message  string `json:"message_hex"`
			Expected string `json:"expected_hex"`
		}
	}
	b, e := os.ReadFile("testdata/native_android_ptm_checksum.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	for i, v := range f.Vectors {
		m, e := hex.DecodeString(v.Message)
		if e != nil {
			t.Fatal(e)
		}
		got := ADIPacketChecksum(m)
		if hex.EncodeToString(got[:]) != v.Expected {
			t.Fatalf("vector%d got%x want%s", i, got, v.Expected)
		}
	}
}
