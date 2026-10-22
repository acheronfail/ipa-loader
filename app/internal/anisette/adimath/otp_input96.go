package adimath

// PrepareOTPInput96 constructs the native pre-expansion message from the
// normalized local prekey and a Unix timestamp. The raw native key allocation
// must first be converted to this semantic 32-byte representation.
func PrepareOTPInput96(normalizedPrekey [32]byte, unixSeconds int64) [96]byte {
	first := OTPDigest32(normalizedPrekey)
	second := OTPDigest64(first.Serialized, first.NextContext)
	third := OTPDigest55(PrepareOTP55(OTPCounter(unixSeconds), OTPPreparationMasks(normalizedPrekey)), NativeOTPDigestContext())
	var input [96]byte
	copy(input[:32], first.Digest[:])
	copy(input[32:64], second[:])
	copy(input[64:], third[:])
	return input
}
