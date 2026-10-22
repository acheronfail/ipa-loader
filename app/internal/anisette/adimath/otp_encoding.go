package adimath

import "encoding/binary"

// OTPEncoding96Context contains expanded byte contributions for the24 observed
// word encodings. Its construction from a profile and32-byte prekey is separate.
// This representation is verified against native synthetic vectors; the compact
// source constructor remains under investigation.
type OTPEncoding96Context struct {
	Baseline [24]uint32
	Columns  [24][4][256]uint32
}

// EncodeOTP96 applies the expanded word encodings to the96-byte input.
func EncodeOTP96(input [96]byte, context *OTPEncoding96Context) [96]byte {
	var output [96]byte
	for word := 0; word < 24; word++ {
		value := context.Baseline[word]
		for column := 0; column < 4; column++ {
			value ^= context.Columns[word][column][input[word*4+column]]
		}
		binary.LittleEndian.PutUint32(output[word*4:], value)
	}
	return output
}
