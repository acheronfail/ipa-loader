package adimath

func rotateMachineByte(value byte, shift uint) byte {
	return value<<shift | value>>(8-shift)
}

// machineRingMix1 is the first bounded UUID-dependent ring mixer recovered
// from macOS adid. The surrounding machine60 construction remains separate.
func machineRingMix1(state *[384]byte) {
	for iteration := uint32(0); iteration < 1536; iteration++ {
		index := iteration % 384
		state[index] = (state[index] ^ rotateMachineByte(state[(index+371)%384], 3)) + rotateMachineByte(state[(index+327)%384], 5) - rotateMachineByte(state[(index+229)%384], 7)
	}
}

func machineRingMix2(state *[384]byte) {
	for iteration := uint32(0); iteration < 1536; iteration++ {
		index := iteration % 384
		// Native arithmetic wraps at 32 bits before taking the remainder.
		state[index] = (state[index] ^ rotateMachineByte(state[(iteration-13)%384], 3)) + rotateMachineByte(state[(iteration-57)%384], 5) - rotateMachineByte(state[(iteration-155)%384], 7)
	}
}
