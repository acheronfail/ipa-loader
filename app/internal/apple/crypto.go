package apple

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
)

const primeHex = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"

func digest(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}
func mac(key []byte, parts ...[]byte) []byte {
	h := hmac.New(sha256.New, key)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}
func integer(b []byte) *big.Int { return new(big.Int).SetBytes(b) }
func pad(n *big.Int) []byte     { return n.FillBytes(make([]byte, 256)) }
func minimum(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) == 0 {
		return []byte{0}
	}
	return b
}

// Fixed-byte s2k/x semantics intentionally retain leading-zero salt and inner
// hash bytes, matching the independently verified reference rather than the
// target's older integer-returning H edge behavior.
func passwordKey(password string, salt []byte, iterations int, protocol string) ([]byte, error) {
	if protocol != "s2k" && protocol != "s2k_fo" {
		return nil, failure("Unsupported Apple password protocol")
	}
	if iterations < 1 || iterations > 10000000 || len(salt) < 1 || len(salt) > 1024 {
		return nil, failure("Invalid Apple password derivation parameters")
	}
	material := digest([]byte(password))
	if protocol == "s2k_fo" {
		material = []byte(hex.EncodeToString(material))
	}
	u := mac(material, salt, []byte{0, 0, 0, 1})
	out := bytes.Clone(u)
	for i := 1; i < iterations; i++ {
		u = mac(material, u)
		for j := range out {
			out[j] ^= u[j]
		}
	}
	return out, nil
}

type srpExchange struct {
	n, g, a, A *big.Int
	user       string
	key, m2    []byte
}

func newSRP(user string, secret []byte) (*srpExchange, error) {
	if secret == nil {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, failure("Could not generate authentication secret")
		}
		secret[0] |= 0x80
	}
	if len(secret) != 32 || integer(secret).Sign() == 0 {
		return nil, failure("Invalid SRP ephemeral secret")
	}
	n, _ := new(big.Int).SetString(primeHex, 16)
	g := big.NewInt(2)
	a := integer(secret)
	return &srpExchange{n: n, g: g, a: a, A: new(big.Int).Exp(g, a, n), user: user}, nil
}
func (s *srpExchange) challenge(password string, response map[string]any) ([]byte, error) {
	salt, err := binaryField(response, "s", -1)
	if err != nil {
		return nil, err
	}
	wireB, err := binaryField(response, "B", -1)
	if err != nil {
		return nil, err
	}
	if len(wireB) < 1 || len(wireB) > 256 {
		return nil, failure("Invalid SRP server public value")
	}
	B := integer(wireB)
	if new(big.Int).Mod(B, s.n).Sign() == 0 {
		return nil, failure("SRP safety check rejected the server challenge")
	}
	iterations, ok := number(response["i"])
	if !ok {
		return nil, failure("Invalid Apple password iteration count")
	}
	protocol, _ := response["sp"].(string)
	p, err := passwordKey(password, salt, iterations, protocol)
	if err != nil {
		return nil, err
	}
	x := integer(digest(salt, digest([]byte(":"), p)))
	clear(p)
	k := integer(digest(pad(s.n), pad(s.g)))
	u := integer(digest(pad(s.A), pad(B)))
	if u.Sign() == 0 {
		return nil, failure("SRP safety check rejected the server challenge")
	}
	v := new(big.Int).Exp(s.g, x, s.n)
	base := new(big.Int).Sub(B, new(big.Int).Mul(k, v))
	base.Mod(base, s.n)
	exponent := new(big.Int).Add(s.a, new(big.Int).Mul(u, x))
	shared := new(big.Int).Exp(base, exponent, s.n)
	s.key = digest(minimum(shared))
	hn, hg := digest(minimum(s.n)), digest(pad(s.g))
	for i := range hn {
		hn[i] ^= hg[i]
	}
	m1 := digest(hn, digest([]byte(s.user)), salt, minimum(s.A), minimum(B), s.key)
	s.m2 = digest(minimum(s.A), m1, s.key)
	return m1, nil
}
func (s *srpExchange) verify(proof []byte) ([]byte, error) {
	if len(proof) != 32 || len(s.m2) != 32 || !hmac.Equal(proof, s.m2) {
		return nil, failure("SRP server proof did not verify")
	}
	return bytes.Clone(s.key), nil
}
func decryptSPD(key, encrypted []byte) (map[string]any, error) {
	if len(key) != 32 || len(encrypted) == 0 || len(encrypted)%aes.BlockSize != 0 {
		return nil, failure("Invalid encrypted session payload")
	}
	block, err := aes.NewCipher(mac(key, []byte("extra data key:")))
	if err != nil {
		return nil, failure("Invalid session encryption key")
	}
	plain := make([]byte, len(encrypted))
	cipher.NewCBCDecrypter(block, mac(key, []byte("extra data iv:"))[:16]).CryptBlocks(plain, encrypted)
	count := int(plain[len(plain)-1])
	if count < 1 || count > 16 || count > len(plain) {
		return nil, failure("Session payload padding did not verify")
	}
	for _, b := range plain[len(plain)-count:] {
		if int(b) != count {
			return nil, failure("Session payload padding did not verify")
		}
	}
	return parsePlist(plain[:len(plain)-count])
}
func decryptToken(key, envelope []byte) (map[string]any, error) {
	if len(key) != 32 || len(envelope) < 35 || !bytes.Equal(envelope[:3], []byte("XYZ")) {
		return nil, failure("Invalid application-token envelope")
	}
	block, _ := aes.NewCipher(key)
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, failure("Invalid application-token encryption")
	}
	plain, err := gcm.Open(nil, envelope[3:19], envelope[19:], envelope[:3])
	if err != nil {
		return nil, failure("Application-token authentication failed")
	}
	return parsePlist(plain)
}
