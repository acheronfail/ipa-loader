package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestCBCBlockNativeSyntheticContext(t *testing.T) {
	// The captured ARM runs used randomly generated tables and key words.
	// These fixtures contain no Apple account or provisioned machine material.
	data, err := os.ReadFile("testdata/native_cbc_synthetic_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Context struct {
			RoundKeys    [44]uint32     `json:"round_keys"`
			Words        [8][256]uint32 `json:"word_tables"`
			Permutations [8][256]byte   `json:"permutations"`
		}
		Vectors []struct{ Plaintext, IV, Ciphertext string }
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	ctx := CBCContext{Words: fixture.Context.Words, Permutations: fixture.Context.Permutations, RoundKeys: fixture.Context.RoundKeys}
	for i, vector := range fixture.Vectors {
		var plain, iv [16]byte
		decode := func(text string, target []byte) {
			t.Helper()
			bytes, err := hex.DecodeString(text)
			if err != nil || len(bytes) != len(target) {
				t.Fatalf("fixture %d has invalid block: %v", i, err)
			}
			copy(target, bytes)
		}
		decode(vector.Plaintext, plain[:])
		decode(vector.IV, iv[:])
		var want [16]byte
		decode(vector.Ciphertext, want[:])
		if got := EncryptCBCBlock(&ctx, plain, iv); got != want {
			t.Fatalf("fixture %d: got %x, want %x", i, got, want)
		}
	}
}
