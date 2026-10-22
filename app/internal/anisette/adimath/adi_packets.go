package adimath

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// ValidateSPIM validates the observed347-byte version4 provisioning challenge.
// The final three bytes are outside the native checksum and are uninterpreted.
func ValidateSPIM(spim []byte) error {
	if len(spim) != 347 || binary.BigEndian.Uint32(spim[:4]) != 4 || binary.BigEndian.Uint32(spim[4:8]) != 240 || binary.BigEndian.Uint32(spim[264:268]) != 52 || binary.BigEndian.Uint32(spim[268:272]) != 4 {
		return errors.New("unsupported SPIM layout")
	}
	checksum := ADIPacketChecksum(spim[4:324])
	if subtle.ConstantTimeCompare(checksum[:], spim[324:344]) != 1 {
		return errors.New("SPIM checksum mismatch")
	}
	return nil
}

// ParsePTM validates the observed version4 packet and returns its CBC fields.
// The returned ciphertext aliases packet. The final seven bytes are outside
// the checksum and are uninterpreted native padding.
func ParsePTM(packet []byte) (iv [16]byte, ciphertext []byte, err error) {
	if len(packet) < 55 || binary.BigEndian.Uint32(packet[:4]) != 4 {
		return iv, nil, errors.New("unsupported PTM layout")
	}
	n := uint64(binary.BigEndian.Uint32(packet[20:24]))
	if n == 0 || n%16 != 0 || n+55 != uint64(len(packet)) {
		return iv, nil, errors.New("invalid PTM ciphertext length")
	}
	end := 24 + int(n)
	if binary.BigEndian.Uint32(packet[end:end+4]) != 0xed9281d8 {
		return iv, nil, errors.New("unsupported PTM trailer")
	}
	checksum := ADIPacketChecksum(packet[4 : end+4])
	if subtle.ConstantTimeCompare(checksum[:], packet[end+4:end+24]) != 1 {
		return iv, nil, errors.New("PTM checksum mismatch")
	}
	copy(iv[:], packet[4:20])
	return iv, packet[24:end], nil
}
