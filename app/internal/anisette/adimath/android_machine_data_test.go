package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestAndroidMachineDigestRepresentationNativeVectors(t *testing.T) {
	var fixture struct {
		Vectors []struct {
			Hash    string `json:"sha1_hex"`
			Encoded string `json:"encoded16_hex"`
			Raw     string `json:"raw_body16_hex"`
			MID     string `json:"mid20_hex"`
		}
	}
	b, e := os.ReadFile("testdata/native_android_machine_digest_representation.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &fixture); e != nil {
		t.Fatal(e)
	}
	for i, v := range fixture.Vectors {
		h, e := hex.DecodeString(v.Hash)
		if e != nil || len(h) != 20 {
			t.Fatalf("vector%d hash", i)
		}
		q := encodeAndroidMachineDigest16([16]byte(h[:16]))
		if hex.EncodeToString(q[:]) != v.Encoded {
			t.Errorf("vector%d encoder", i)
		}
		r := TransformAndroidMachineDigestBlock(q)
		if hex.EncodeToString(r[:]) != v.Raw {
			t.Errorf("vector%d block", i)
		}
		mid := decodeAndroidMachineDigest16(r)
		got := append(mid[:], h[16:]...)
		if hex.EncodeToString(got) != v.MID {
			t.Errorf("vector%d semanticMID", i)
		}
	}
}

func TestGenerateAndroidMachineDataNativeVectors(t *testing.T) {
	var fixture struct {
		Vectors []struct{ Identity, Entropy40, Machine60 string }
	}
	b, err := os.ReadFile("testdata/native_android_machine_data_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Vectors) != 4 {
		t.Fatalf("expectedfourfullnativeidentitycases,got%d", len(fixture.Vectors))
	}
	for i, v := range fixture.Vectors {
		id, e := hex.DecodeString(v.Identity)
		if e != nil || len(id) != 16 {
			t.Fatalf("vector%d identity", i)
		}
		entropy, e := hex.DecodeString(v.Entropy40)
		if e != nil || len(entropy) != 40 {
			t.Fatalf("vector%d entropy", i)
		}
		got := GenerateAndroidMachineData([16]byte(id), [40]byte(entropy))
		if hex.EncodeToString(got[:]) != v.Machine60 {
			t.Errorf("vector%d got%x want%s", i, got, v.Machine60)
		}
	}
}
