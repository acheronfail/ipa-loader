// Package adimath implements recovered ADI provisioning and OTP arithmetic in
// pure Go. It does not perform Apple HTTP exchanges or account authentication.
//
// Synthetic differential fixtures cover this native PRNG model. It exists
// for reference comparisons; fresh Go state uses crypto/rand instead.
package adimath

const (
	MTWords = 624
	// StateXOR is the observed encoding of each native state word.
	StateXOR uint32 = 0x41b8241e
	// TemperOutputXOR applies to tempering an already encoded native word.
	TemperOutputXOR uint32 = 0xe6596876
)

// EncodedMT reproduces the recovered native state/output boundary. The selected
// native path twists the entire state on EVERY call, then tempers the selected
// word. This differs from the usual MT19937 Next algorithm, which consumes all
// 624 words between twists. Index is the decoded native index, not its biased
// in-memory representation.
type EncodedMT struct {
	Words [MTWords]uint32
	Index uint32
}

// SeedEncodedMT reproduces the observed 624-word seed initialization. The caller
// supplies the index; this does not claim to recover engine initialization order
// or which index the engine chooses after seeding.
func SeedEncodedMT(seed, index uint32) EncodedMT {
	var out EncodedMT
	out.Index = index
	x := seed
	out.Words[0] = x ^ StateXOR
	for i := 1; i < MTWords; i++ {
		x = 1812433253*(x^(x>>30)) + uint32(i)
		out.Words[i] = x ^ StateXOR
	}
	return out
}

// TemperMT19937 is the ordinary uint32 tempering expression. For the observed
// native encoded input word x, the register result is this value XOR
// TemperOutputXOR. This function alone does not advance generator state.
func TemperMT19937(x uint32) uint32 {
	x ^= x >> 11
	x ^= (x << 7) & 0x9d2c5680
	x ^= (x << 15) & 0xefc60000
	x ^= x >> 18
	return x
}

// Next advances the state and returns the encoded native register result. The
// result is not identified here as a protocol nonce, an OTP, or CPIM data.
func (m *EncodedMT) Next() uint32 {
	// Decode first because the in-place recurrence uses some already-updated
	// tap words. Removing the mask only on reads would encode those twice.
	for i := range m.Words {
		m.Words[i] ^= StateXOR
	}
	for i := range m.Words {
		y := (m.Words[i] & 0x80000000) | (m.Words[(i+1)%MTWords] & 0x7fffffff)
		x := m.Words[(i+397)%MTWords] ^ (y >> 1)
		if y&1 != 0 {
			x ^= 0x9908b0df
		}
		m.Words[i] = x
	}
	for i := range m.Words {
		m.Words[i] ^= StateXOR
	}
	if m.Index >= MTWords {
		m.Index = 0
	}
	out := TemperMT19937(m.Words[m.Index]) ^ TemperOutputXOR
	m.Index++
	return out
}
