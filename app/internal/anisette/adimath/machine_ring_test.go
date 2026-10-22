package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestMachineRingNativeVectors(t *testing.T) {
	var fixture struct {
		Vectors []struct {
			Stage  int    `json:"stage"`
			Input  string `json:"input"`
			Output string `json:"output"`
		} `json:"vectors"`
	}
	raw, err := os.ReadFile("testdata/native_machine_ring_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Vectors) != 4 {
		t.Fatal("expected four native vectors")
	}
	for i, v := range fixture.Vectors {
		data, err := hex.DecodeString(v.Input)
		if err != nil || len(data) != 384 {
			t.Fatalf("invalid vector%d", i)
		}
		var state [384]byte
		copy(state[:], data)
		switch v.Stage {
		case 1:
			machineRingMix1(&state)
		case 2:
			machineRingMix2(&state)
		default:
			t.Fatalf("unknown stage%d", v.Stage)
		}
		if hex.EncodeToString(state[:]) != v.Output {
			t.Errorf("vector%d differs from native", i)
		}
	}
}
