package adimath

import "math/bits"

// machineUUIDBridge folds the shaped ring and mixes the resulting variable-length key.
// The representation masks are removed here at their respective native boundaries.
func machineUUIDBridge(ring [384]byte, initial [169]byte, maskA, maskB [64]byte, length int) (expanded [384]byte, seed uint32) {
	key := make([]byte, length)
	copy(key, initial[:32])
	for i := 0; i < 64; i++ {
		key[i] ^= maskA[i] ^ maskB[i]
	}
	for i, v := range ring {
		key[i%length] ^= v
	}
	// The next mixer consumes the prior byte representation under a different mask.
	for i := range key {
		key[i] ^= 0xdc
	}
	for i := 0; i < 256; i++ {
		j := i % length
		key[j] ^= bits.RotateLeft8(key[(j+length-7)%length], 1) ^ bits.RotateLeft8(key[(j+length-37)%length], 6) ^ bits.RotateLeft8(key[(j+length-177%length)%length], 5)
	}
	for i := 0; i < length+172; i++ {
		seed = (seed + 14*uint32(key[i%length]%41)) % 41
	}
	for i := range expanded {
		expanded[i] = key[i%length]
	}
	return
}
