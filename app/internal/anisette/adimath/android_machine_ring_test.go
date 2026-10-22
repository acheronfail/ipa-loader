package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestAndroidMachineRingNativeVectors(t *testing.T) {
	var fixture struct {
		Vectors []struct{ Input, Output string }
	}
	b, e := os.ReadFile("testdata/native_android_machine_ring_vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &fixture); e != nil {
		t.Fatal(e)
	}
	for i, v := range fixture.Vectors {
		b, e := hex.DecodeString(v.Input)
		if e != nil || len(b) != 328 {
			t.Fatalf("vector%d input", i)
		}
		state := [328]byte(b)
		androidMachineRing(&state)
		if hex.EncodeToString(state[:]) != v.Output {
			t.Errorf("vector%d differs", i)
		}
	}
}
