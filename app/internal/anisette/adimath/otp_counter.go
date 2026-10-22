package adimath

// OTPCounter returns the low 32 bits of the native signed 30-second quotient.
// Native negative timestamps truncate toward zero, as Go integer division does.
func OTPCounter(unixSeconds int64) uint32 { return uint32(unixSeconds / 30) }

// EncodeOTPCounter8 reproduces the observed eight-byte internal counter field.
// counter is the low32 bits of the previously computed30-second bucket. This
// field is followed by other input construction; it is not a standard TOTP
// counter encoding. Synthetic differential fixtures cover this representation.
func EncodeOTPCounter8(counter uint32) [8]byte {
	biased := counter + 0x18e3f2bc
	alternate := biased + 0x698d4467
	if biased+0x50a951ab > 0x698d4466 {
		alternate = biased
	}
	a := uint32((uint64(counter) * 0x12e0a56b) >> 32)
	b := counter - uint32((uint64(counter)*0x7b85ee89)>>57)*0x04251cd7
	c := counter - ((a+((counter-a)>>1))>>29)*0x3b9acf71
	c = c - (0x240c4b24 & (c << 1)) + 0x52062592
	b = b - (0x0630effc & (b << 1)) + 0x3b1877fe
	d := alternate + 0xe71c0d44
	e := counter - uint32((uint64(counter)*0x9c715473)>>61)*0x345d3da7
	e = e - (0x0e8191c8 & (e << 1)) + 0x0740c8e4
	return [8]byte{
		byte(0x19 ^ (c >> 8)), byte(c ^ 0xae),
		byte(((d >> 8) - (0xa2 & (d >> 7)) + 0x51) ^ 0x6d),
		byte((alternate ^ 0x80) - (((alternate << 1) + 8) & 0x78)),
		byte(0x4b ^ (b >> 8)), byte(b ^ 0xc2),
		byte(0xf4 ^ (e >> 8)), byte(e ^ 0xd8),
	}
}
