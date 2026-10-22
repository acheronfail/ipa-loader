package adimath

// ExpandOTPContext derives the final body context and its encoded message from
// the decoded profile, normalized local key bytes, and prepared 96-byte message.
// DecodeOTPProfile384 supplies decodedProfile. Preparing the message and
// normalizing the local key are separate frontend operations.
func ExpandOTPContext(decodedProfile [384]byte, normalizedPrekey [32]byte, input [96]byte) (OTPBodyContext, [96]byte) {
	return otpContextFromExpansion(otpExpandArithmetic(decodedProfile, HashOTPPrekey32(normalizedPrekey), input))
}
func otpContextFromExpansion(words [167]uint32) (ctx OTPBodyContext, encoded [96]byte) {
	copy(ctx.State[:], words[:4])
	for i := range ctx.EncodingWords {
		ctx.EncodingWords[i] = uint64(words[4+i])
	}
	copy(ctx.RoundWords[:], words[11:59])
	params := OTPTableParams{Permute: [4]byte{byte(words[59]), byte(words[60]), byte(words[61]), byte(words[62])}}
	params.OutputXOR = [8]uint32{words[64], words[65], words[66], words[67], words[68], words[69], words[63], words[70]}
	ctx.Tables = BuildOTPTables(params)
	for i := range encoded {
		encoded[i] = byte(words[71+i])
	}
	return
}
