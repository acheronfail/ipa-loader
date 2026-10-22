package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestAndroidMachineSuffixFold(t *testing.T) {
	var fixture struct {
		Vectors []struct {
			Input   string   `json:"input"`
			Outputs []string `json:"outputs"`
		} `json:"vectors"`
	}
	raw, e := os.ReadFile("testdata/native_android_machine_suffix_vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &fixture); e != nil {
		t.Fatal(e)
	}
	for i, v := range fixture.Vectors {
		input, _ := hex.DecodeString(v.Input)
		ring, key := androidMachineSuffix([328]byte(input))
		got := [][]byte{ring[:], key[:]}
		for j, out := range got {
			if hex.EncodeToString(out) != v.Outputs[j] {
				t.Errorf("vector%d output%d differs", i, j)
			}
		}
	}
}
