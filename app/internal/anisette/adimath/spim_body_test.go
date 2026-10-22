package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestTransformSPIMBodyNativeVectors(t *testing.T) {
	var fixture struct {
		Vectors []struct {
			Input  string `json:"input"`
			Output string `json:"output"`
		} `json:"vectors"`
	}
	data, e := os.ReadFile("testdata/native_spim_body_vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(data, &fixture); e != nil {
		t.Fatal(e)
	}
	for i, v := range fixture.Vectors {
		raw, e := hex.DecodeString(v.Input)
		if e != nil || len(raw) != 240 {
			t.Fatal("invalid input fixture")
		}
		var in [240]byte
		copy(in[:], raw)
		out := TransformSPIMBody(in)
		if hex.EncodeToString(out[:]) != v.Output {
			t.Fatalf("vector%d output differs", i)
		}
	}
}
