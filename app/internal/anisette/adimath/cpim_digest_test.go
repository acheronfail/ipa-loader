package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestCPIMDigestNativeVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/native_cpim_digest_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Ciphertext string `json:"ciphertext_hex"`
			Block      string `json:"challenge_block_hex"`
			Digest     string `json:"digest_hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Vectors) != 2 {
		t.Fatal("expected two native vectors")
	}
	for i, v := range fixture.Vectors {
		var cipher [160]byte
		var block [16]byte
		decode := func(s string, dst []byte) {
			b, err := hex.DecodeString(s)
			if err != nil || len(b) != len(dst) {
				t.Fatalf("vector %d: invalid fixture", i)
			}
			copy(dst, b)
		}
		decode(v.Ciphertext, cipher[:])
		decode(v.Block, block[:])
		got := CPIMDigest(cipher, block)
		if hex.EncodeToString(got[:]) != v.Digest {
			t.Errorf("vector %d: digest differs from native output", i)
		}
	}
}
