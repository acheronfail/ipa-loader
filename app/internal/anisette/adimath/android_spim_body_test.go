package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestAndroidSPIMBodySyntheticNativeVectors(t *testing.T) {
	b, e := os.ReadFile("testdata/native_android_spim_body_vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var rows []struct{ Input, Output string }
	if e = json.Unmarshal(b, &rows); e != nil {
		t.Fatal(e)
	}
	for i, r := range rows {
		raw, e := hex.DecodeString(r.Input)
		if e != nil || len(raw) != 240 {
			t.Fatal("bad synthetic input")
		}
		want, e := hex.DecodeString(r.Output)
		if e != nil || len(want) != 240 {
			t.Fatal("bad native output")
		}
		var input [240]byte
		copy(input[:], raw)
		got := TransformAndroidSPIMBody(input)
		if string(got[:]) != string(want) {
			t.Fatalf("vector%d differs", i)
		}
	}
}
