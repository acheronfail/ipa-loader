package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestAndroidChecksumBackendNative(t *testing.T) {
	b, err := os.ReadFile("testdata/native_android_checksum_backend.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Encoded string `json:"encoded16_hex"`
			Digest  string `json:"sha1_hex"`
			Wire    string `json:"wire20_hex"`
		}
	}
	if err = json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	for i, v := range fixture.Vectors {
		var encoded, digest [16]byte
		raw, err := hex.DecodeString(v.Encoded)
		if err != nil || len(raw) != 16 {
			t.Fatal("invalid fixture encoding")
		}
		copy(encoded[:], raw)
		h, err := hex.DecodeString(v.Digest)
		if err != nil || len(h) != 20 {
			t.Fatal("invalid fixture digest")
		}
		copy(digest[:], h)
		direct := TransformAndroidChecksumBlock(encoded)
		composed := TransformAndroidDigest16(digest)
		if direct != composed || hex.EncodeToString(direct[:]) != v.Wire[:32] || v.Digest[32:] != v.Wire[32:] {
			t.Errorf("vector%d direct%x composed%x want%s", i, direct, composed, v.Wire)
		}
	}
}
