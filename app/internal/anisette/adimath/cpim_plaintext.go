package adimath

import "encoding/binary"

// CPIMPlaintextInputs describes the recovered macOS 160-byte plaintext boundary.
// FirstFieldInput is decoded data before TransformCPIMField32. The complete
// derivation of these inputs, including MachineData, belongs to ADI start and
// is not implemented by this structure.
type CPIMPlaintextInputs struct {
	FirstFieldInput [32]byte
	SecondField     [32]byte
	MachineData     [60]byte
	Environment     int64
	UnixSeconds     uint32
	Padding         [12]byte
}

// BuildCPIMPlaintext encodes the observed fields before CBC encryption. The
// fixed word 1 is retained from the recovered path, without assigning it a
// broader version negotiation meaning. Native padding bytes are not PKCS#7.
func BuildCPIMPlaintext(fields CPIMPlaintextInputs) (plaintext [160]byte) {
	return buildCPIMPlaintext(fields, TransformCPIMField32(fields.FirstFieldInput), 1)
}

// BuildAndroidCPIMPlaintext uses the normalized local OTP key as FirstFieldInput
// and the observed Android client word4. Other field meanings are unchanged.
func BuildAndroidCPIMPlaintext(fields CPIMPlaintextInputs) [160]byte {
	return buildCPIMPlaintext(fields, TransformAndroidCPIMField32(fields.FirstFieldInput), 4)
}

func buildCPIMPlaintext(fields CPIMPlaintextInputs, first [32]byte, clientWord uint32) (plaintext [160]byte) {
	binary.BigEndian.PutUint32(plaintext[:4], 32)
	copy(plaintext[4:36], first[:])
	binary.BigEndian.PutUint32(plaintext[36:40], 32)
	copy(plaintext[40:72], fields.SecondField[:])
	copy(plaintext[72:132], fields.MachineData[:])
	binary.BigEndian.PutUint64(plaintext[132:140], uint64(fields.Environment))
	binary.BigEndian.PutUint32(plaintext[140:144], fields.UnixSeconds)
	binary.BigEndian.PutUint32(plaintext[144:148], clientWord)
	copy(plaintext[148:], fields.Padding[:])
	return plaintext
}
