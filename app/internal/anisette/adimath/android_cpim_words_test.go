package adimath

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestAndroidCPIMWordBanksSyntheticNativeVectors(t *testing.T) {
	b, e := os.ReadFile("testdata/native_android_cpim_words.json")
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
		banks := BuildAndroidCPIMByteBanks(seed)
		for k := range banks {
			var seen [256]bool
			for _, v := range banks[k] {
				if seen[v] {
					t.Fatalf("synthetic case%d bank%d is singular", ci, k)
				}
				seen[v] = true
			}
		}
		got := buildAndroidCPIMWordBanks(&banks)
		for k := range got {
			want, e := hex.DecodeString(r.Banks[k])
			if e != nil || len(want) != 1024 {
				t.Fatal("invalid bank")
			}
			for i, v := range got[k] {
				if v != binary.LittleEndian.Uint32(want[4*i:]) {
					t.Fatalf("case%d bank%d word%d differs", ci, k, i)
				}
			}
		}
	}
}
