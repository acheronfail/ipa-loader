package adimath

// GenerateAndroidMachineData reproduces the inspected Android ADI machine-data
// generator using an explicit 16-byte client identity and 40 bytes of fresh local
// entropy. It calls no native library, service, clock, or host identity API.
func GenerateAndroidMachineData(identity [16]byte, entropy [40]byte) (machine [60]byte) {
	digest := androidMachineDigest(identity)
	encoded := encodeAndroidMachineDigest16([16]byte(digest[:16]))
	raw := TransformAndroidMachineDigestBlock(encoded)
	prefix := decodeAndroidMachineDigest16(raw)
	copy(machine[:16], prefix[:])
	copy(machine[16:20], digest[16:])
	copy(machine[20:], entropy[:])
	return
}

func encodeAndroidMachineDigest16(input [16]byte) (encoded [16]byte) {
	for i, v := range input {
		encoded[i] = v ^ byte(65*i) ^ 0x07
	}
	return
}

// This mask removes the canonical byte representation used by the lifted
// machine cipher. Eight independent hashes match the complete native encoder,
// rebuilt banks, block transform and semantic MID serialization.
func decodeAndroidMachineDigest16(input [16]byte) (decoded [16]byte) {
	mask := [16]byte{0xa1, 0x29, 0x91, 0xfd, 0xc4, 0x8f, 0x10, 0xfa, 0x2a, 0xd8, 0xb8, 0xd6, 0x63, 0x94, 0x4f, 0x9a}
	for i, v := range input {
		decoded[i] = v ^ mask[i]
	}
	return
}
