package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestTransformChallengeBlockNativeVectors(t *testing.T) {
	var fixture struct {
		Vectors []struct {
			Input  string `json:"input"`
			Output string `json:"output"`
		} `json:"vectors"`
	}
	b, e := os.ReadFile("testdata/native_challenge_block_vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &fixture); e != nil {
		t.Fatal(e)
	}
	for _, v := range fixture.Vectors {
		t.Run(v.Input, func(t *testing.T) {
			in, _ := hex.DecodeString(v.Input)
			got := TransformChallengeBlock([16]byte(in))
			if hex.EncodeToString(got[:]) != v.Output {
				t.Fatalf("got %x want%s", got, v.Output)
			}
		})
	}
}
