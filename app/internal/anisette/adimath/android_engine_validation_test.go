package adimath

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"strconv"
	"strings"
	"testing"
)

// Deterministic random SPIM body, seed495405/candidate31713. It was selected
// solely because its decoded affine maps are bijections. This is synthetic
// arithmetic input, not an Apple-issued challenge or a provisioned identity.
const syntheticEngineSPIMHex = "00000004000000f0216eaa874538e0025f297ad9351c489ba6c3a97161b9e024afefdd088b372ff3ea3aa9fa7ecc500051be2a3a2798ee9427270a5937927f90a5f62cc6fb59576183bf6bceff04e9c8d1018b9a62b59c34d7c5b85c3cfc3f9494a4456a8f0cf5eb76642bb93941c8ef8f267963d8fa6ab27e10df10050df1e00d19679a515725ed7c33e0b2ad6619bf2b51a8bdedc83ba0d39b5ee221688e72392e4390c39ac9bec91f7586e57e5505b35af4274cf16ed4c1fdeda6eda122e91892f1a1adb715d7a5a7e33b73d7390d40f5e3f1cc080717f26817126507456e82eff005e89f34f68173c4250980528d71f21e8326ac4ef6edc722069210dacfc3c526ebd3a8f06b0000003400000004e87f278618a0a44b7cf510e570627ea942adba18a9ec438f5dbd523029b35b04b4ab3446c5f62e2d819ce4d55a493fbc802b4d353f814c1ca5978c430209f2986a5f3df29055a18a000000"

func engineSyntheticSPIM(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(syntheticEngineSPIMHex)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func engineSyntheticPTM(iv [16]byte, ciphertext []byte) []byte {
	p := make([]byte, len(ciphertext)+55)
	binary.BigEndian.PutUint32(p[:4], 4)
	copy(p[4:20], iv[:])
	binary.BigEndian.PutUint32(p[20:24], uint32(len(ciphertext)))
	copy(p[24:], ciphertext)
	end := 24 + len(ciphertext)
	binary.BigEndian.PutUint32(p[end:end+4], 0xed9281d8)
	c := ADIPacketChecksum(p[4 : end+4])
	copy(p[end+4:end+24], c[:])
	return p
}

func TestSPIMValidationBoundaries(t *testing.T) {
	valid := engineSyntheticSPIM(t)
	if err := ValidateSPIM(valid); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(valid); n++ {
		if ValidateSPIM(valid[:n]) == nil {
			t.Fatalf("truncated SPIM accepted at%d", n)
		}
	}
	for _, tc := range []struct {
		name   string
		offset int
		value  uint32
	}{{"version", 0, 5}, {"body length", 4, 239}, {"tail length", 264, 51}, {"tail version", 268, 3}} {
		t.Run(tc.name, func(t *testing.T) {
			p := bytes.Clone(valid)
			binary.BigEndian.PutUint32(p[tc.offset:tc.offset+4], tc.value)
			c := ADIPacketChecksum(p[4:324])
			copy(p[324:344], c[:])
			if ValidateSPIM(p) == nil {
				t.Fatal("unsupported layout accepted despite valid checksum")
			}
		})
	}
	for _, off := range []int{8, 248, 272, 324} {
		t.Run("protected_byte_"+strconv.Itoa(off), func(t *testing.T) {
			p := bytes.Clone(valid)
			p[off] ^= 1
			if ValidateSPIM(p) == nil {
				t.Fatalf("modified protected byte%d accepted", off)
			}
		})
	}
	p := bytes.Clone(valid)
	for i := 344; i < 347; i++ {
		p[i] ^= 0xff
	}
	if err := ValidateSPIM(p); err != nil {
		t.Fatalf("uninterpreted trailing bytes rejected:%v", err)
	}
	if ValidateSPIM(append(bytes.Clone(valid), 0)) == nil {
		t.Fatal("oversized SPIM accepted")
	}
}

func TestPTMValidationBoundaries(t *testing.T) {
	var iv [16]byte
	for i := range iv {
		iv[i] = byte(i + 7)
	}
	cipher := bytes.Repeat([]byte{0x63}, 32)
	valid := engineSyntheticPTM(iv, cipher)
	gotIV, got, err := ParsePTM(valid)
	if err != nil || gotIV != iv || !bytes.Equal(got, cipher) {
		t.Fatal("valid synthetic frame rejected", err)
	}
	for n := 0; n < len(valid); n++ {
		if _, _, e := ParsePTM(valid[:n]); e == nil {
			t.Fatalf("truncated PTM accepted at%d", n)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"version", func(p []byte) { p[3] = 3 }},
		{"zero ciphertext", func(p []byte) { binary.BigEndian.PutUint32(p[20:24], 0) }},
		{"unaligned ciphertext", func(p []byte) { binary.BigEndian.PutUint32(p[20:24], 31) }},
		{"overflow length", func(p []byte) { binary.BigEndian.PutUint32(p[20:24], 0xfffffff0) }},
		{"declared length", func(p []byte) { binary.BigEndian.PutUint32(p[20:24], 48) }},
		{"trailer magic", func(p []byte) { p[56] ^= 1 }},
		{"IV checksum", func(p []byte) { p[4] ^= 1 }},
		{"ciphertext checksum", func(p []byte) { p[24] ^= 1 }},
		{"checksum", func(p []byte) { p[60] ^= 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := bytes.Clone(valid)
			tc.mutate(p)
			if _, _, e := ParsePTM(p); e == nil {
				t.Fatal("malformed packet accepted")
			}
		})
	}
	p := bytes.Clone(valid)
	for i := len(p) - 7; i < len(p); i++ {
		p[i] ^= 0xff
	}
	if _, _, e := ParsePTM(p); e != nil {
		t.Fatalf("uninterpreted trailing bytes rejected:%v", e)
	}
	if _, _, e := ParsePTM(append(bytes.Clone(valid), 0)); e == nil {
		t.Fatal("oversized PTM accepted")
	}
	valid[24] ^= 0x20
	if got[0] != valid[24] {
		t.Fatal("documented ciphertext alias was lost")
	}
}

func TestStartAndroidProvisioningRetention(t *testing.T) {
	spim := engineSyntheticSPIM(t)
	var fields CPIMPlaintextInputs
	fields.Environment = -2
	fields.UnixSeconds = 1800000000
	for i := range fields.FirstFieldInput {
		fields.FirstFieldInput[i] = byte(i*7 + 1)
		fields.SecondField[i] = byte(i*3 + 4)
	}
	for i := range fields.MachineData {
		fields.MachineData[i] = byte(i*11 + 5)
	}
	session, cpim, err := StartAndroidProvisioning(spim, fields, [16]byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	if session.Prekey != fields.FirstFieldInput || session.Nonce != fields.SecondField || session.MID != fields.MachineData || session.Environment != -2 || !bytes.Equal(session.SPIM[:], spim) {
		t.Fatal("start lost local values needed by finish/OTP")
	}
	if !bytes.Equal(cpim[216:], spim[264:324]) {
		t.Fatal("CPIM lost its challenge tail binding")
	}
	spim[8] ^= 1
	if bytes.Equal(session.SPIM[:], spim) {
		t.Fatal("retained challenge aliases caller buffer")
	}
	spim[0] ^= 1 // Unsupported framing must fail before any local state is retained.
	failed, packet, e := StartAndroidProvisioning(spim, fields, [16]byte{})
	if e == nil || failed != (AndroidProvisioningSession{}) || packet != ([276]byte{}) {
		t.Fatal("invalid challenge returned partial session state")
	}
}

// Build an independently synthetic valid finish layout without an encryption
// oracle: CBC lets IV bytes select the first header, and C23 select P24's header.
// The affected earlier plaintext block is merely opaque profile data. Retaining
// the resulting random binding creates a consistent local session for this test.
func engineSyntheticFinishFixture(t *testing.T) (AndroidProvisioningSession, [16]byte, []byte, []byte) {
	t.Helper()
	var s AndroidProvisioningSession
	copy(s.SPIM[:], engineSyntheticSPIM(t))
	s.Environment = -2
	for i := range s.Prekey {
		s.Prekey[i] = byte(i*13 + 8)
	}
	for i := range s.MID {
		s.MID[i] = byte(i*5 + 9)
	}
	ctx, err := ProvisioningCipherContext(s.SPIM[:])
	if err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewSource(90814))
	var tk, iv [16]byte
	r.Read(tk[:])
	r.Read(iv[:])
	cipher := make([]byte, 432)
	r.Read(cipher)
	plain, err := DecryptAndroidPTM(&ctx, tk, iv, cipher)
	if err != nil {
		t.Fatal(err)
	}
	var profileLen, bindingLen [4]byte
	binary.BigEndian.PutUint32(profileLen[:], 384)
	binary.BigEndian.PutUint32(bindingLen[:], 32)
	for i := 0; i < 4; i++ {
		iv[i] ^= plain[i] ^ profileLen[i]
		cipher[23*16+4+i] ^= plain[388+i] ^ bindingLen[i]
	}
	plain, err = DecryptAndroidPTM(&ctx, tk, iv, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(plain[:4]) != 384 || binary.BigEndian.Uint32(plain[388:392]) != 32 {
		t.Fatal("CBC fixture headers inconsistent")
	}
	copy(s.Nonce[:], plain[392:424])
	return s, tk, engineSyntheticPTM(iv, cipher), plain
}

func TestFinishAndroidProvisioningSyntheticStateAndRejections(t *testing.T) {
	session, tk, packet, plain := engineSyntheticFinishFixture(t)
	state, err := FinishAndroidProvisioning(session, packet, tk)
	if err != nil {
		t.Fatal(err)
	}
	if state.Prekey != session.Prekey || state.MID != session.MID || state.Environment != session.Environment || !bytes.Equal(state.Profile[:], plain[4:388]) {
		t.Fatal("finish returned wrong retained/profile state")
	}
	for _, tc := range []struct {
		name, want string
		session    func(*AndroidProvisioningSession)
		packet     func([]byte) []byte
	}{
		{name: "binding", want: "binding", session: func(s *AndroidProvisioningSession) { s.Nonce[0] ^= 1 }},
		{name: "profile length", want: "layout", packet: func(p []byte) []byte {
			var iv [16]byte
			copy(iv[:], p[4:20])
			iv[3] ^= 1
			return engineSyntheticPTM(iv, p[24:456])
		}},
		{name: "binding length", want: "layout", packet: func(p []byte) []byte {
			var iv [16]byte
			copy(iv[:], p[4:20])
			c := bytes.Clone(p[24:456])
			c[23*16+7] ^= 1
			return engineSyntheticPTM(iv, c)
		}},
		{name: "protected ciphertext", want: "checksum", packet: func(p []byte) []byte { p[24] ^= 1; return p }},
		{name: "different profile format", want: "length", packet: func(p []byte) []byte { return engineSyntheticPTM([16]byte{}, make([]byte, 448)) }},
		{name: "corrupt retained challenge", want: "SPIM", session: func(s *AndroidProvisioningSession) { s.SPIM[0] ^= 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := session
			p := bytes.Clone(packet)
			if tc.session != nil {
				tc.session(&s)
			}
			if tc.packet != nil {
				p = tc.packet(p)
			}
			got, e := FinishAndroidProvisioning(s, p, tk)
			if e == nil || !strings.Contains(e.Error(), tc.want) {
				t.Fatalf("wanted%q rejection, got%v", tc.want, e)
			}
			if got != (AndroidMachineState{}) {
				t.Fatal("failed finish returned partial secret state")
			}
		})
	}
}

func TestProvisioningRejectsChecksumValidSingularChallenge(t *testing.T) {
	p := engineSyntheticSPIM(t)
	clear(p[8:248]) // This synthetic body decodes to several non-bijective maps.
	checksum := ADIPacketChecksum(p[4:324])
	copy(p[324:344], checksum[:])
	if err := ValidateSPIM(p); err != nil {
		t.Fatalf("fixture checksum/layout invalid:%v", err)
	}
	context, err := ProvisioningCipherContext(p)
	if err == nil || !strings.Contains(err.Error(), "singular") {
		t.Fatalf("singular context accepted:%v", err)
	}
	if context != (CBCContext{}) {
		t.Fatal("failed context derivation returned partial key state")
	}
	session, cpim, err := StartAndroidProvisioning(p, CPIMPlaintextInputs{}, [16]byte{})
	if err == nil || session != (AndroidProvisioningSession{}) || cpim != ([276]byte{}) {
		t.Fatal("singular challenge returned partial start state")
	}
}
