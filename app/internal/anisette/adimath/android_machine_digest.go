package adimath

import (
	"crypto/sha1"
	"math/bits"
)

// androidMachineDigest derives the identity-dependent digest before the final
// digest16 transform. It accepts an explicit16-byte synthetic/client identity.
func androidMachineDigest(identity [16]byte) [20]byte {
	var ring [328]byte
	for i := range ring {
		ring[i] = identity[i%16]
	}
	androidMachineRing(&ring)
	ring, prefix, a, b := androidMachinePrefix(ring)
	ring = androidMachineBridge(ring, prefix, a, b, androidMachineKeyLength(identity))
	androidMachineRing2(&ring)
	ring, message := androidMachineSuffix(ring)
	for i, v := range ring {
		message[i%20] ^= v
	}
	for i := uint32(0); i < 256; i++ {
		j := i % 20
		message[j] ^= bits.RotateLeft8(message[(i-7)%20], 1) ^ bits.RotateLeft8(message[(i-37)%20], 6) ^ bits.RotateLeft8(message[(i-177)%20], 5)
	}
	return sha1.Sum(message[:18])
}
