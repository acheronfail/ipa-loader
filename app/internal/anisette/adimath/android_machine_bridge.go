package adimath

import "math/bits"

func androidMachineKeyLength(identity [16]byte) int {
	seed := uint32(5)
	for i := 0; i < 371; i++ {
		seed = (seed + 121 - uint32(identity[i%16]%121)) % 121
	}
	return int(80 + seed)
}

// androidMachineBridge folds the shaped ring into a variable-length key,
// mixes it256times, and expands it for the second328-byte ring pass.
func androidMachineBridge(ring [328]byte, prefix [32]byte, mask [64]byte, maskB [64]byte, length int) (expanded [328]byte) {
	key := make([]byte, length)
	for i := range key {
		key[i] = 0x35
	}
	copy(key, prefix[:])
	for i, v := range mask {
		key[i%length] ^= v ^ maskB[i]
	}
	for i, v := range ring {
		key[i%length] ^= v
	}
	for i := 0; i < 256; i++ {
		j := i % length
		key[j] ^= bits.RotateLeft8(key[(j+length-7)%length], 1) ^ bits.RotateLeft8(key[(j+length-37)%length], 6) ^ bits.RotateLeft8(key[(j+length-177%length)%length], 5)
	}
	for i := range expanded {
		expanded[i] = key[i%length]
	}
	return
}
