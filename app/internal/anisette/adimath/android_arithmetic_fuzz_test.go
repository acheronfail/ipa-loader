package adimath

import (
	"crypto/sha512"
	"encoding/binary"
	"testing"
)

// Native differential vectors check output correctness. This complementary
// fuzz target exercises input-dependent lookup addresses and branch boundaries
// across the composed arithmetic, including malformed packet checksum inputs.
func FuzzAndroidArithmetic(f *testing.F) {
	f.Add([]byte("independent ADI arithmetic"))
	f.Add([]byte{0, 0xff, 0x80})
	f.Fuzz(func(t *testing.T, seed []byte) {
		var stream [448]byte
		for i := 0; i < 7; i++ {
			h := sha512.New()
			h.Write(seed)
			h.Write([]byte{byte(i)})
			copy(stream[64*i:], h.Sum(nil))
		}
		var key [32]byte
		copy(key[:], stream[:32])
		var profile [384]byte
		copy(profile[:], stream[32:416])
		seconds := int64(binary.LittleEndian.Uint64(stream[416:424]))
		otp := GenerateAndroidOTP(key, profile, seconds)
		_ = TransformAndroidCPIMField32(key)
		if binary.BigEndian.Uint32(otp[:4]) != 5 || binary.BigEndian.Uint32(otp[4:8]) != 16 || binary.BigEndian.Uint32(otp[24:]) != 4 {
			t.Fatal("invalid OTP frame")
		}
		var identity [16]byte
		copy(identity[:], stream[424:440])
		var tail [40]byte
		copy(tail[:], stream[:40])
		mid := GenerateAndroidMachineData(identity, tail)
		if [40]byte(mid[20:]) != tail {
			t.Fatal("machine entropy changed")
		}
		_ = ADIPacketChecksum(stream[:])
	})
}
