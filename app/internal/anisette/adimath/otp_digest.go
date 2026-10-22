// Recovered arithmetic retained as source; synthetic regression vectors cover this implementation.
package adimath

import (
	"encoding/binary"
	"math/bits"
)

// OTPDigestContext supplies the explicit boundary of one observed55-byte transform.
// Initial contains eight live words; Constants contains the64read words.
// Their source reconstruction is separate from this arithmetic primitive.
type OTPDigestContext struct {
	Initial   OTPCompressionState
	Constants [64]uint32
}

// OTPDigest55 reproduces the observed bounded arithmetic, not a named standard hash.
func OTPDigest55(message [55]byte, context OTPDigestContext) [32]byte {
	var padded [64]byte
	copy(padded[:55], message[:])
	padded[55] = 0x80
	binary.BigEndian.PutUint64(padded[56:], 440)
	var w [64]uint32
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(padded[4*i:])
	}
	for i := 16; i < 64; i++ {
		a, b, c, d := w[i-16], w[i-15], w[i-7], w[i-2]
		s0 := (bits.RotateLeft32(b, -7) ^ bits.RotateLeft32(b, -18)) + (b >> 3)
		s1 := (bits.RotateLeft32(d, -17) - bits.RotateLeft32(d, -19)) ^ (d >> 10)
		w[i] = (s0 ^ c ^ s1) - a
	}
	state := context.Initial
	var r [31]uint32
	var temp [4]uint32
	for i := 0; i < 64; i++ {
		r, temp = otpCompressionRoundRaw(state, context.Constants[i], w[i]^0x37323615, i == 63)
		state = OTPCompressionState{r[0], r[5], r[9], r[10], r[14], r[19], r[22], r[25]}
	}
	var result [32]byte
	r[9] = uint32(0x6a7f)
	r[9] = (r[9] &^ uint32(0xffff0000)) | uint32(0x49b60000)
	r[11] = temp[2]
	r[8] = r[7] ^ r[9]
	r[9] = r[14] ^ r[9]
	r[14] = uint32(0xd5e6)
	r[6] = temp[3]
	r[14] = (r[14] &^ uint32(0xffff0000)) | uint32(0x814f0000)
	r[16] = uint32(0x2264)
	r[10] = uint32(0xd4fe)
	r[16] = (r[16] &^ uint32(0xffff0000)) | uint32(0xb7ce0000)
	r[2] = uint32(0x165c)
	r[14] = r[14] + (r[15] << 1)
	r[10] = (r[10] &^ uint32(0xffff0000)) | uint32(0x936c0000)
	r[17] = uint32(0x3759)
	r[2] = (r[2] &^ uint32(0xffff0000)) | uint32(0xac2b0000)
	r[4] = uint32(0x4346)
	r[16] = r[16] + (r[11] << 1)
	r[14] = r[14] & r[10]
	r[17] = (r[17] &^ uint32(0xffff0000)) | uint32(0xe0ac0000)
	r[4] = (r[4] &^ uint32(0xffff0000)) | uint32(0x8fc00000)
	r[2] = r[2] + (r[6] << 1)
	r[16] = r[16] & r[10]
	r[14] = r[15] - r[14]
	r[17] = r[5] ^ r[17]
	r[5] = r[12]
	r[4] = r[4] + (r[12] << 1)
	r[2] = r[2] & r[10]
	r[12] = r[11] - r[16]
	r[16] = uint32(0xf5ad)
	r[11] = r[6] - r[2]
	r[16] = (r[16] &^ uint32(0xffff0000)) | uint32(0x9fcb0000)
	r[11] = r[11] + r[16]
	r[0] = uint32(0x1738)
	r[3] = uint32(0x2e8c)
	binary.LittleEndian.PutUint32(result[4:], r[11])
	r[0] = (r[0] &^ uint32(0xffff0000)) | uint32(0xd5080000)
	r[3] = (r[3] &^ uint32(0xffff0000)) | uint32(0xe1700000)
	r[0] = r[0] + (r[9] << 1)
	r[3] = r[3] + (r[8] << 1)
	r[4] = r[4] & r[10]
	r[15] = uint32(0x8c22)
	r[0] = r[0] & r[10]
	r[3] = r[3] & r[10]
	r[10] = r[5] - r[4]
	r[15] = (r[15] &^ uint32(0xffff0000)) | uint32(0x11960000)
	r[10] = r[10] + r[15]
	binary.LittleEndian.PutUint32(result[24:], r[10])
	r[1] = uint32(0x769e)
	r[1] = (r[1] &^ uint32(0xffff0000)) | uint32(0xfe00000)
	r[1] = r[25] ^ r[1]
	binary.LittleEndian.PutUint32(result[28:], r[17])
	r[11] = uint32(0x5572)
	r[11] = (r[11] &^ uint32(0xffff0000)) | uint32(0xa5e0000)
	r[11] = r[14] + r[11]
	binary.LittleEndian.PutUint32(result[16:], r[1])
	r[8] = r[8] - r[3]
	r[9] = r[9] - r[0]
	r[6] = uint32(0x5a83)
	binary.LittleEndian.PutUint32(result[20:], r[11])
	r[11] = uint32(0x7bb1)
	r[11] = (r[11] &^ uint32(0xffff0000)) | uint32(0x259d0000)
	r[11] = r[12] + r[11]
	binary.LittleEndian.PutUint32(result[12:], r[11])
	r[11] = uint32(0x81c5)
	r[11] = (r[11] &^ uint32(0xffff0000)) | uint32(0xba6e0000)
	r[8] = r[8] + r[11]
	binary.LittleEndian.PutUint32(result[8:], r[8])
	r[10] = uint32(0x761b)
	r[10] = (r[10] &^ uint32(0xffff0000)) | uint32(0x343a0000)
	r[9] = r[9] + r[10]
	binary.LittleEndian.PutUint32(result[0:], r[9])
	return result
}
