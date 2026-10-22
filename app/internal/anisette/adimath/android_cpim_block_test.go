package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestAndroidCipherSyntheticNativeVectors(t *testing.T) {
	b, e := os.ReadFile("testdata/native_android_cipher_vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var rows []struct{ Material, Input, IV, Output string }
	if e = json.Unmarshal(b, &rows); e != nil {
		t.Fatal(e)
	}
	for ci, r := range rows {
		raw, _ := hex.DecodeString(r.Material)
		if len(raw) != 240 {
			t.Fatal("invalid material")
		}
		var material [240]byte
		copy(material[:], raw)
		ctx, e := BuildAndroidCPIMContext(material)
		if e != nil {
			t.Fatal(e)
		}
		var input, iv [16]byte
		raw, _ = hex.DecodeString(r.Input)
		copy(input[:], raw)
		raw, _ = hex.DecodeString(r.IV)
		copy(iv[:], raw)
		want, _ := hex.DecodeString(r.Output)
		got := EncryptAndroidCPIMBlock(&ctx, input, iv)
		if string(got[:]) != string(want) {
			t.Fatalf("case%d differs", ci)
		}
	}
}
func TestAndroidContextRejectsSingularBanks(t *testing.T) {
	b, e := os.ReadFile("testdata/native_android_cpim_permutations.json")
	if e != nil {
		t.Fatal(e)
	}
	var rows []struct{ Seed string }
	if e = json.Unmarshal(b, &rows); e != nil {
		t.Fatal(e)
	}
	raw, _ := hex.DecodeString(rows[0].Seed)
	var material [240]byte
	copy(material[176:], raw)
	if _, e = BuildAndroidCPIMContext(material); e == nil {
		t.Fatal("singular banks accepted")
	}
}
