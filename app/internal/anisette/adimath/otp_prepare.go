package adimath

// PrepareOTP55 constructs the observed counter-dependent55-byte transform input.
// masks is the16-byte expanded key context in native read order. Deriving that
// context from a persisted ADI identity is separate from this primitive.
func PrepareOTP55(counter uint32, masks [16]byte) [55]byte {
	var result [55]byte
	encoded := EncodeOTPCounter8(counter)
	for i, b := range encoded {
		result[i] = b ^ 0x3c
	}
	state := byte(0xf9)
	for i := 0; i < 96; i++ {
		j := (i + 7) % len(result)
		result[j] ^= masks[i%len(masks)] + (state ^ 0x6a)
		state ^= 68 * result[j]
	}
	return result
}

// OTPPreparationMasks selects the odd bytes of the normalized local prekey.
// The normalized key is also the input to HashOTPPrekey32; a native pointer-
// encoded allocation must be decoded before passing it to this function.
func OTPPreparationMasks(normalizedPrekey [32]byte) [16]byte {
	var masks [16]byte
	for i := range masks {
		masks[i] = normalizedPrekey[2*i+1]
	}
	return masks
}
