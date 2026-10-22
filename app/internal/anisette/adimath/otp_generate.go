package adimath

import "encoding/binary"

// GenerateAndroidOTP reproduces the recovered Android 28-byte OTP payload from
// semantic local key bytes, the 384-byte profile field, and Unix time. It does
// not provision an identity, parse persisted state, or authenticate an account.
func GenerateAndroidOTP(normalizedPrekey [32]byte, profile [384]byte, unixSeconds int64) [28]byte {
	input := PrepareOTPInput96(normalizedPrekey, unixSeconds)
	context, encoded := ExpandOTPContext(DecodeOTPProfile384(profile), normalizedPrekey, input)
	body := ComputeOTPBody(&context, encoded)
	var output [28]byte
	binary.BigEndian.PutUint32(output[:4], 5)
	binary.BigEndian.PutUint32(output[4:8], uint32(len(body)))
	copy(output[8:24], body[:])
	binary.BigEndian.PutUint32(output[24:], 4)
	return output
}
