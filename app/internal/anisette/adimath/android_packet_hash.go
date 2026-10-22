package adimath

import "crypto/sha1"

// ADIPacketChecksum computes the recovered SPIM/PTM checksum representation. Its
// first16 SHA-1 bytes pass through the checksum-role transform; the final four
// pass unchanged. Other ADI hash roles may select different native contexts.
func ADIPacketChecksum(message []byte) [20]byte {
	digest := sha1.Sum(message)
	var first [16]byte
	copy(first[:], digest[:16])
	encoded := TransformAndroidDigest16(first)
	copy(digest[:16], encoded[:])
	return digest
}
