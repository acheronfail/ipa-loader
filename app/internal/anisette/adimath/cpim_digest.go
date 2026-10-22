package adimath

import "crypto/sha256"

// CPIMDigest reproduces the recovered macOS CPIM trailer. challengeBlock is
// the 16-byte intermediate produced by TransformChallengeBlock. It is not the SPIM itself. ciphertext is the 160-byte CBC field.
//
// This primitive alone cannot construct a valid provisioning response.
// Synthetic differential fixtures cover this primitive.
func CPIMDigest(ciphertext [160]byte, challengeBlock [16]byte) [32]byte {
	mask := [16]byte{0x05, 0x0e, 0xbc, 0xea, 0x2f, 0xff, 0xae, 0xbd, 0xa8, 0x14, 0xb5, 0x59, 0xd3, 0xcd, 0xc8, 0xdd}
	salt := [24]byte{0x37, 0x95, 0x02, 0x0c, 0x05, 0xf7, 0x70, 0x09, 0xcb, 0xfe, 0xaa, 0x78, 0xa5, 0xbc, 0xb3, 0x17, 0x5b, 0xad, 0x60, 0xb9, 0xde, 0xaa, 0xaa, 0x8d}
	var input [200]byte
	copy(input[:160], ciphertext[:])
	for i := range challengeBlock {
		input[160+i] = challengeBlock[i] ^ mask[i]
	}
	copy(input[176:], salt[:])
	return sha256.Sum256(input[:])
}
