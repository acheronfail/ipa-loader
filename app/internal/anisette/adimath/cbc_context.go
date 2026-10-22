package adimath

import "encoding/binary"

// BuildCBCContext constructs the numeric CPIM cipher context from the 240 bytes
// returned by TransformSPIMBody. This recovers the start-response block context;
// it does not provide ADI provisioning completion or OTP generation.
func BuildCBCContext(material [240]byte) CBCContext {
	var ctx CBCContext
	for i := range ctx.RoundKeys {
		ctx.RoundKeys[i] = binary.LittleEndian.Uint32(material[i*4:])
	}
	var seed [16]uint32
	for i := range seed {
		seed[i] = binary.LittleEndian.Uint32(material[176+i*4:])
	}
	for i := uint32(0); i < 256; i++ {
		values, indexes := contextPerm(seed, i)
		for bank := range values {
			ctx.Permutations[bank][indexes[bank]] = values[bank]
		}
	}
	for i := uint32(0); i < 256; i++ {
		values, indexes := contextWords(&ctx.Permutations, i)
		for bank := range values {
			ctx.Words[bank][indexes[bank]] = values[bank]
		}
	}
	// An all-zero representation seed selects this mask. Changing the encoding
	// changes the tables and this mask together; it does not change ciphertext.
	ctx.EncodingDelta = 0xdecae46f
	return ctx
}
