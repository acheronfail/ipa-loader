package adimath

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func checkNativeSyntheticOTPTables(t *testing.T, path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Params struct {
			Permute   [4]byte   `json:"permute"`
			OutputXOR [8]uint32 `json:"output_xor"`
		} `json:"params"`
		Tables []string `json:"expected_tables_le_hex"`
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	got := BuildOTPTables(OTPTableParams{Permute: fixture.Params.Permute, OutputXOR: fixture.Params.OutputXOR})
	if len(fixture.Tables) != 8 {
		t.Fatal("incomplete native table fixture")
	}
	for table, s := range fixture.Tables {
		expected, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		if len(expected) != 1024 {
			t.Fatalf("table%d length%d", table, len(expected))
		}
		for i, v := range got[table] {
			want := binary.LittleEndian.Uint32(expected[i*4:])
			if v != want {
				t.Fatalf("table%d[%d]=%08x, native=%08x", table, i, v, want)
			}
		}
	}
}

func TestNativeSyntheticOTPTables(t *testing.T) {
	for _, path := range []string{"testdata/native_otp_tables.json", "testdata/native_otp_tables_random.json"} {
		t.Run(path, func(t *testing.T) { checkNativeSyntheticOTPTables(t, path) })
	}
}
