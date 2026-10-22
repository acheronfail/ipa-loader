package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestAndroidMachineBridgeNativeVectors(t *testing.T) {
	var fixture struct {
		Vectors []struct {
			Ring, Prefix, Mask, Output string
			MaskB                      string `json:"mask_b"`
			Length                     int
		}
	}
	b, e := os.ReadFile("testdata/native_android_machine_bridge_vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &fixture); e != nil {
		t.Fatal(e)
	}
	for i, v := range fixture.Vectors {
		r, _ := hex.DecodeString(v.Ring)
		p, _ := hex.DecodeString(v.Prefix)
		m, _ := hex.DecodeString(v.Mask)
		mb, _ := hex.DecodeString(v.MaskB)
		got := androidMachineBridge([328]byte(r), [32]byte(p), [64]byte(m), [64]byte(mb), v.Length)
		if hex.EncodeToString(got[:]) != v.Output {
			t.Errorf("vector%d differs", i)
		}
	}
}
