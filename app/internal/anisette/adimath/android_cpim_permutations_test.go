package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestAndroidCPIMByteBanksSyntheticNativeVectors(t *testing.T) {
	b, e := os.ReadFile("testdata/native_android_cpim_permutations.json")
	if e != nil {
		t.Fatal(e)
	}
	var rows []struct {
		Seed  string
		Banks []string
	}
	if e = json.Unmarshal(b, &rows); e != nil {
		t.Fatal(e)
	}
	for ci, r := range rows {
		raw, e := hex.DecodeString(r.Seed)
		if e != nil || len(raw) != 64 || len(r.Banks) != 8 {
			t.Fatal("invalid fixture")
		}
		var seed [64]byte
		copy(seed[:], raw)
		got := BuildAndroidCPIMByteBanks(seed)
		for k := range got {
			want, e := hex.DecodeString(r.Banks[k])
			if e != nil || len(want) != 256 {
				t.Fatal("invalid bank")
			}
			if string(got[k][:]) != string(want) {
				t.Fatalf("case%d bank%d differs", ci, k)
			}
		}
	}
}
