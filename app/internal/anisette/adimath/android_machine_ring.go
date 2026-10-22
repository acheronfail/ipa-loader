package adimath

import "math/bits"

// androidMachineRing mixes decoded machine-binding bytes. The Android artifact
// uses328bytes; its arithmetic agrees with all1312native updates.
func androidMachineRing(state *[328]byte) {
	for i := 0; i < 1312; i++ {
		j := i % 328
		state[j] = (state[j] ^ bits.RotateLeft8(state[(j+315)%328], 3)) + bits.RotateLeft8(state[(j+271)%328], 5) - bits.RotateLeft8(state[(j+173)%328], 7)
	}
}

// androidMachineRing2 preserves uint32 underflow before computing lag indices.
func androidMachineRing2(state *[328]byte) {
	for i := uint32(0); i < 1312; i++ {
		j := i % 328
		state[j] = (state[j] ^ bits.RotateLeft8(state[(i-13)%328], 3)) + bits.RotateLeft8(state[(i-57)%328], 5) - bits.RotateLeft8(state[(i-155)%328], 7)
	}
}
