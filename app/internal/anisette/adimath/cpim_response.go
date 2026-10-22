package adimath

import "encoding/binary"

// ComposeCPIM joins the recovered macOS CPIM fields. It requires the prepared
// plaintext and encoded cipher context, whose derivation is not implemented by
// this function. challengeBlock is the output of TransformChallengeBlock.
// tail is the observed 60-byte copy of SPIM[264:324].
//
// This is a recovered response-construction boundary, not a complete ADI start
// operation. It does not generate randomness, fetch SPIM, or provision state.
func ComposeCPIM(ctx *CBCContext, plaintext [160]byte, iv, challengeBlock [16]byte, tail [60]byte) (response [276]byte) {
	binary.BigEndian.PutUint32(response[:4], 5)
	copy(response[4:20], iv[:])
	binary.BigEndian.PutUint32(response[20:24], 160)
	var ciphertext [160]byte
	chain := iv
	for i := 0; i < len(plaintext); i += 16 {
		var block [16]byte
		copy(block[:], plaintext[i:i+16])
		chain = EncryptCBCBlock(ctx, block, chain)
		copy(ciphertext[i:i+16], chain[:])
	}
	copy(response[24:184], ciphertext[:])
	digest := CPIMDigest(ciphertext, challengeBlock)
	copy(response[184:216], digest[:])
	copy(response[216:], tail[:])
	return response
}
