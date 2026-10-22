package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestAndroidMachineDigestNativeVectors(t *testing.T) {
	var fixture struct {
		Vectors []struct {
			Identity, Preimage, Digest string
			PreimageLength             int `json:"preimage_length"`
		}
	}
	b, err := os.ReadFile("testdata/native_android_machine_digest_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	for i, v := range fixture.Vectors {
		identity, err := hex.DecodeString(v.Identity)
		if err != nil || len(identity) != 16 {
			t.Fatalf("vector%d identity", i)
		}
		got := androidMachineDigest([16]byte(identity))
		if hex.EncodeToString(got[:]) != v.Digest {
			t.Errorf("vector%d got%x want%s", i, got, v.Digest)
		}
		if v.PreimageLength != 18 {
			t.Fatalf("vector%d nativeSHA1preimagelen%d", i, v.PreimageLength)
		}
	}
}
