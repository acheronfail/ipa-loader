package adimath

import "errors"

// ProvisioningCipherContext derives the shared provisioning cipher from a
// checked SPIM. Singular permutation maps are rejected rather than reading the
// uninitialized scratch bytes left by the native implementation.
func ProvisioningCipherContext(spim []byte) (CBCContext, error) {
	if err := ValidateSPIM(spim); err != nil {
		return CBCContext{}, err
	}
	var body [240]byte
	copy(body[:], spim[8:248])
	context := BuildCBCContext(TransformSPIMBody(body))
	for _, permutation := range context.Permutations {
		var seen [256]bool
		for _, value := range permutation {
			if seen[value] {
				return CBCContext{}, errors.New("singular SPIM permutation")
			}
			seen[value] = true
		}
	}
	return context, nil
}

// PrepareCPIM assembles the recovered response for the observed 347-byte SPIM
// layout. fields must already contain local machine data and semantic entropy;
// NewAndroidProvisioning generates fresh fields for the Android format.
//
// The SPIM version and field lengths are restricted to the two native research
// fixtures. Other ADI formats have not been recovered by this implementation.
func PrepareCPIM(spim []byte, fields CPIMPlaintextInputs, iv [16]byte) ([276]byte, error) {
	return prepareCPIMPlaintext(spim, BuildCPIMPlaintext(fields), iv)
}

// PrepareAndroidCPIM uses the shared provisioning cipher with the Android local
// key binding and client word. The normalized local key is FirstFieldInput.
func PrepareAndroidCPIM(spim []byte, fields CPIMPlaintextInputs, iv [16]byte) ([276]byte, error) {
	return prepareCPIMPlaintext(spim, BuildAndroidCPIMPlaintext(fields), iv)
}

func prepareCPIMPlaintext(spim []byte, plaintext [160]byte, iv [16]byte) ([276]byte, error) {
	context, err := ProvisioningCipherContext(spim)
	if err != nil {
		return [276]byte{}, err
	}
	mask := [16]byte{0x9b, 0x82, 0x9a, 0xf2, 0x5d, 0xd7, 0xe1, 0xe0, 0x2a, 0xb7, 0x73, 0x60, 0x76, 0x52, 0xe4, 0xac}
	var challengeInput [16]byte
	for i := range challengeInput {
		challengeInput[i] = spim[248+i] ^ mask[i]
	}
	challenge := TransformChallengeBlock(challengeInput)
	var tail [60]byte
	copy(tail[:], spim[264:324])
	return ComposeCPIM(&context, plaintext, iv, challenge, tail), nil
}
