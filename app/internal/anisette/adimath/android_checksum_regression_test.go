package adimath

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestChecksumReadonlyPageNativeRegressions(t *testing.T) {
	b, err := os.ReadFile("testdata/native_checksum_page_regressions.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Message string `json:"message_hex"`
			Wire    string `json:"wire20_hex"`
		}
	}
	if err = json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	for i, v := range fixture.Vectors {
		message, err := hex.DecodeString(v.Message)
		if err != nil {
			t.Fatal(err)
		}
		got := ADIPacketChecksum(message)
		if hex.EncodeToString(got[:]) != v.Wire {
			t.Errorf("vector%d got%x want%s", i, got, v.Wire)
		}
	}
}
func TestChecksumArbitraryNativeBlocks(t *testing.T) {
	b, err := os.ReadFile("testdata/native_checksum_arbitrary.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Input  string `json:"input16_hex"`
			Output string `json:"output16_hex"`
		}
	}
	if err = json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	for i, v := range fixture.Vectors {
		raw, err := hex.DecodeString(v.Input)
		if err != nil || len(raw) != 16 {
			t.Fatal("invalid fixture input")
		}
		var input [16]byte
		copy(input[:], raw)
		got := TransformAndroidChecksumBlock(input)
		if hex.EncodeToString(got[:]) != v.Output {
			t.Fatalf("vector%d got%x want%s", i, got, v.Output)
		}
	}
}
