package adimath

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestOTPEncodingNativeSynthetic(t *testing.T) {
	b, e := os.ReadFile("testdata/native_otp_encoding_context.bin")
	if e != nil {
		t.Fatal(e)
	}
	if len(b) != 96+24*4*256*4 {
		t.Fatal("invalidnumericcontextlength")
	}
	var context OTPEncoding96Context
	for i := range context.Baseline {
		context.Baseline[i] = binary.LittleEndian.Uint32(b[4*i:])
	}
	offset := 96
	for word := range context.Columns {
		for column := range context.Columns[word] {
			for value := range context.Columns[word][column] {
				context.Columns[word][column][value] = binary.LittleEndian.Uint32(b[offset:])
				offset += 4
			}
		}
	}
	b, e = os.ReadFile("testdata/native_otp_encoding.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Vectors []struct {
			Input  string `json:"input96_hex"`
			Output string `json:"output96_hex"`
		}
	}
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	for i, v := range f.Vectors {
		a, e := hex.DecodeString(v.Input)
		if e != nil || len(a) != 96 {
			t.Fatal("invalidfixtureinput")
		}
		var input [96]byte
		copy(input[:], a)
		got := EncodeOTP96(input, &context)
		if hex.EncodeToString(got[:]) != v.Output {
			t.Fatalf("vector%d got%x want%s", i, got, v.Output)
		}
	}
}
