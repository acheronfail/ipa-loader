package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestTransformCPIMField32NativeVectors(t *testing.T) {
	var fixture struct {
		Vectors []struct {
			Input  string `json:"input"`
			Output string `json:"output"`
		} `json:"vectors"`
	}
	data, err := os.ReadFile("testdata/native_cpim_field32_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Vectors) != 16 {
		t.Fatal("expected sixteen native vectors")
	}
	for index, v := range fixture.Vectors {
		raw, err := hex.DecodeString(v.Input)
		if err != nil || len(raw) != 32 {
			t.Fatalf("vector%d invalid input fixture", index)
		}
		var input [32]byte
		copy(input[:], raw)
		output := TransformCPIMField32(input)
		if hex.EncodeToString(output[:]) != v.Output {
			t.Errorf("vector%d output differs from native", index)
		}
	}
}
