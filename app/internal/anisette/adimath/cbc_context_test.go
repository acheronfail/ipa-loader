package adimath

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestBuildCBCContextNativeSynthetic(t *testing.T) {
	raw, err := os.ReadFile("testdata/native_cbc_context_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Seed         string
		Permutations [8][256]byte
		Words        [8][256]uint32 `json:"word_tables"`
	}
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	for caseIndex, row := range rows {
		seed, err := hex.DecodeString(row.Seed)
		if err != nil {
			t.Fatal(err)
		}
		var material [240]byte
		copy(material[176:], seed)
		for i := 0; i < 44; i++ {
			binary.LittleEndian.PutUint32(material[i*4:], uint32(i)*0x15263749+0x12345678)
		}
		got := BuildCBCContext(material)
		if got.Permutations != row.Permutations {
			t.Fatalf("case %d permutation mismatch", caseIndex)
		}
		if got.Words != row.Words {
			t.Fatalf("case %d word-table mismatch", caseIndex)
		}
		for i, key := range got.RoundKeys {
			if key != binary.LittleEndian.Uint32(material[i*4:]) {
				t.Fatalf("case %d round-key %d mismatch", caseIndex, i)
			}
		}
		if got.EncodingDelta != 0xdecae46f {
			t.Fatalf("case %d encoding mask mismatch", caseIndex)
		}
	}
}

func TestConstructedContextCipherNativeSynthetic(t *testing.T) {
	raw, err := os.ReadFile("testdata/native_cbc_context_cipher_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct{ Material, Plaintext, IV, Ciphertext string }
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	for i, row := range rows {
		var material [240]byte
		var plain, iv, want [16]byte
		for _, item := range []struct {
			text   string
			target []byte
		}{{row.Material, material[:]}, {row.Plaintext, plain[:]}, {row.IV, iv[:]}, {row.Ciphertext, want[:]}} {
			decoded, err := hex.DecodeString(item.text)
			if err != nil {
				t.Fatal(err)
			}
			if len(decoded) != len(item.target) {
				t.Fatalf("case %d fixture length", i)
			}
			copy(item.target, decoded)
		}
		ctx := BuildCBCContext(material)
		got := EncryptCBCBlock(&ctx, plain, iv)
		if got != want {
			t.Fatalf("case %d got %x want %x", i, got, want)
		}
	}
}
