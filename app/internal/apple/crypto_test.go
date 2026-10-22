package apple

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func unhex(value string) []byte {
	b, e := hex.DecodeString(value)
	if e != nil {
		panic(e)
	}
	return b
}

// Fixed SRP outputs for synthetic username, password and salt inputs.
func TestSRPFixedVectors(t *testing.T) {
	vectors := []struct{ protocol, B, M1, M2, K string }{
		{"s2k", "4a5942df95727b42235e342c31435530cfc8df05169fe152d27b7c3f4a6c0243b007dd20d20c526fa5f05cae90a7b1896ecec7477a97e9d43ae803ebfa426f84a4df3eafd1a8893842ac0884dc2ad3cd9aff3387e302d6719d4830297c0301a1d85fe85a7aa4a581f7545d2cb4dd5b65598146337a7d4d7b4f11d6bc3693f341647d1ba2bbc8932e0cc34b4a60757f93d18c69272f820b051d3784e845ef39ee774385a71d1a3c95b5a9f58599963f1baa9c2a875a54598cfb46ac65cac793b94262ae1d44f4092c011c66f018c4397f72f6b779d4502a18d244f457c9e7b189fdc5754662ea65e2989e64e77e4ae6e59f574736e1918e230ce2164883bab41d", "5e22243bab9eb378d0069ee0ac4415ee145dc1c0f070049462adf81ab09c561b", "4140711ebbfc660d4a5d1ae3331f7c4d91987ccd19822a5bf9503a06c833a6df", "44425efb493a3419e56683919d657fc38468037a412cf85cb41ddacb868fa6e1"},
		{"s2k_fo", "0cfa613563896304409123961e0ac2a903781703f27a451f3bd7bb285305c9523a875c87f757be2ae55a23380770970c384b04143f78cb5a758c1950281d89224eec2e596c47b87f97fd8e4a87d2077efc3e9dea021194e47541565d28e2086d2d9d8e54c3fca9370d25d59ff57300e93e3bae742d63c30c915b2a56c120ceefb7df7f03b93bb9beb8ea8524eafea4c4f9141f19e094537dddacef39169b07b04c4f7c098221032f49231bcfc58c528c2e09a3797f47527ae81fa8094842b9091dc83433d77afc80e62d74440c3287ced22562fb0383f07e84e7710eeecda1d0e9b4eeaf376ec2803cdbb3c8fa27160079a999b1f0675e8e9d3454d6c03c5f93", "56a60da610c14004c1536b85f9785d94cb56f376aa20ac5c946a0d38398e5dd2", "f7cebec5598cbc1f27c61a8db18696d3a43a058f0de309e58b794a157ffca811", "9328cf69ed2f9625cc906a02de723f544f5473bb3e5d2897b99f860239ab8822"},
	}
	for _, v := range vectors {
		t.Run(v.protocol, func(t *testing.T) {
			s, e := newSRP("offline@example.invalid", bytes.Repeat([]byte{0x17}, 32))
			if e != nil {
				t.Fatal(e)
			}
			salt := make([]byte, 16)
			for i := range salt {
				salt[i] = byte(i)
			}
			m, e := s.challenge("synthetic password only!", map[string]any{"s": salt, "B": unhex(v.B), "i": 1000, "sp": v.protocol})
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(m, unhex(v.M1)) {
				t.Fatal("M1 differs from independent oracle")
			}
			k, e := s.verify(unhex(v.M2))
			if e != nil || !bytes.Equal(k, unhex(v.K)) {
				t.Fatal("server proof/key differs from independent oracle")
			}
			if _, e = s.verify(make([]byte, 32)); e == nil {
				t.Fatal("bad proof accepted")
			}
		})
	}
}
func TestSRPSafetyChecks(t *testing.T) {
	s, _ := newSRP("u", bytes.Repeat([]byte{1}, 32))
	for _, b := range [][]byte{nil, {0}, make([]byte, 257), s.n.Bytes()} {
		if _, e := s.challenge("p", map[string]any{"s": []byte{1}, "B": b, "i": 1, "sp": "s2k"}); e == nil {
			t.Fatal("invalid server public accepted")
		}
	}
	if _, e := newSRP("u", make([]byte, 32)); e == nil {
		t.Fatal("zero secret accepted")
	}
	for _, sp := range []string{"bad", ""} {
		if _, e := passwordKey("p", []byte{1}, 1, sp); e == nil {
			t.Fatal("unknown protocol accepted")
		}
	}
}
