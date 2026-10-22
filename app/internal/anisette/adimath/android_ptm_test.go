package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestAndroidPostTKFactorySyntheticNativeVectors(t *testing.T) {
	b, e := os.ReadFile("testdata/native_android_post_tk_vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var rows []struct {
		EncryptedTK               string `json:"encrypted_tk"`
		IV, Ciphertext, Plaintext string
	}
	if e = json.Unmarshal(b, &rows); e != nil {
		t.Fatal(e)
	}
	for ci, r := range rows {
		var encryptedTK, iv [16]byte
		raw, e := hex.DecodeString(r.EncryptedTK)
		if e != nil || len(raw) != 16 {
			t.Fatal("invalid encrypted TK")
		}
		copy(encryptedTK[:], raw)
		raw, e = hex.DecodeString(r.IV)
		if e != nil || len(raw) != 16 {
			t.Fatal("invalid IV")
		}
		copy(iv[:], raw)
		ciphertext, e := hex.DecodeString(r.Ciphertext)
		if e != nil || len(ciphertext)%16 != 0 {
			t.Fatal("invalid ciphertext")
		}
		want, e := hex.DecodeString(r.Plaintext)
		if e != nil {
			t.Fatal(e)
		}
		ctx := newAndroidPTMContextFromEncryptedTK(encryptedTK)
		out := make([]byte, len(ciphertext))
		previous := iv
		for off := 0; off < len(ciphertext); off += 16 {
			var input [16]byte
			copy(input[:], ciphertext[off:off+16])
			v := decryptAndroidPTMBlock(&ctx, input)
			for i := range v {
				out[off+i] = v[i] ^ previous[i]
			}
			previous = input
		}
		if string(out) != string(want) {
			t.Fatalf("vector%d differs", ci)
		}
	}
}
