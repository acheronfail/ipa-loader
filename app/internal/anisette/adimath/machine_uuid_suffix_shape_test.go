package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestUUIDSuffixShapeFold(t *testing.T) {
	var fixture struct {
		Vectors []struct {
			Input   string   `json:"input"`
			Outputs []string `json:"outputs"`
		} `json:"vectors"`
	}
	raw, e := os.ReadFile("testdata/native_machine_uuid_suffix_shape_vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &fixture); e != nil {
		t.Fatal(e)
	}
	for i, v := range fixture.Vectors {
		input, _ := hex.DecodeString(v.Input)
		ring, a, b := machineUUIDSuffixShape([384]byte(input))
		got := [][]byte{ring[:], a[:], b[:]}
		for j, out := range got {
			if hex.EncodeToString(out) != v.Outputs[j] {
				t.Errorf("vector%d output%d differs", i, j)
			}
		}
	}
}
