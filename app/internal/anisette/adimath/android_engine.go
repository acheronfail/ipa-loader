package adimath

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// NewAndroidProvisioning creates fresh local secret state for the recovered
// environment -2 format. identity is a stable client-selected16-byte
// device identity. Randomness comes from crypto/rand rather than the native MT.
func NewAndroidProvisioning(spim []byte, identity [16]byte, unixSeconds uint32) (AndroidProvisioningSession, [276]byte, error) {
	// Reject invalid packets before consuming fresh entropy.
	if err := ValidateSPIM(spim); err != nil {
		return AndroidProvisioningSession{}, [276]byte{}, err
	}
	var entropy [132]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return AndroidProvisioningSession{}, [276]byte{}, err
	}
	defer clear(entropy[:])
	var fields CPIMPlaintextInputs
	copy(fields.FirstFieldInput[:], entropy[:32])
	copy(fields.SecondField[:], entropy[32:64])
	var tail [40]byte
	copy(tail[:], entropy[64:104])
	fields.MachineData = GenerateAndroidMachineData(identity, tail)
	var iv [16]byte
	copy(iv[:], entropy[104:120])
	copy(fields.Padding[:], entropy[120:132])
	fields.Environment = -2
	fields.UnixSeconds = unixSeconds
	return StartAndroidProvisioning(spim, fields, iv)
}

// AndroidProvisioningSession retains the local values needed to finish one
// provisioning exchange. It contains secret key material and must be protected
// if persisted. Android names the recovered profile format, not a Go OS limit.
type AndroidProvisioningSession struct {
	SPIM        [347]byte
	Prekey      [32]byte
	Nonce       [32]byte
	MID         [60]byte
	Environment int64
}

// AndroidMachineState holds the independent engine's provisioned secret state.
// Profile is the encrypted 384-byte profile returned by the provisioning server.
type AndroidMachineState struct {
	Prekey      [32]byte
	Profile     [384]byte
	MID         [60]byte
	Environment int64
}

// StartAndroidProvisioning constructs CPIM and retains its matching local state.
// Inputs are explicit to support reproducible native differential comparisons.
func StartAndroidProvisioning(spim []byte, fields CPIMPlaintextInputs, iv [16]byte) (session AndroidProvisioningSession, cpim [276]byte, err error) {
	cpim, err = PrepareAndroidCPIM(spim, fields, iv)
	if err != nil {
		return session, cpim, err
	}
	copy(session.SPIM[:], spim)
	session.Prekey = fields.FirstFieldInput
	session.Nonce = fields.SecondField
	session.MID = fields.MachineData
	session.Environment = fields.Environment
	return session, cpim, nil
}

// FinishAndroidProvisioning validates and decrypts PTM using its matching SPIM
// and TK, then checks the server's binding to the retained start nonce.
func FinishAndroidProvisioning(session AndroidProvisioningSession, ptm []byte, tk [16]byte) (state AndroidMachineState, err error) {
	iv, ciphertext, err := ParsePTM(ptm)
	if err != nil {
		return state, err
	}
	if len(ciphertext) != 432 {
		return state, errors.New("unsupported Android PTM plaintext length")
	}
	context, err := ProvisioningCipherContext(session.SPIM[:])
	if err != nil {
		return state, err
	}
	plain, err := DecryptAndroidPTM(&context, tk, iv, ciphertext)
	if err != nil {
		return state, err
	}
	defer clear(plain)
	if binary.BigEndian.Uint32(plain[:4]) != 384 || binary.BigEndian.Uint32(plain[388:392]) != 32 {
		return state, errors.New("unsupported Android PTM profile layout")
	}
	if subtle.ConstantTimeCompare(plain[392:424], session.Nonce[:]) != 1 {
		return state, errors.New("PTM nonce binding mismatch")
	}
	state.Prekey = session.Prekey
	copy(state.Profile[:], plain[4:388])
	state.MID = session.MID
	state.Environment = session.Environment
	return state, nil
}

// OTP computes a fresh machine authentication value from retained local state.
func (state *AndroidMachineState) OTP(unixSeconds int64) (mid [60]byte, otp [28]byte) {
	return state.MID, GenerateAndroidOTP(state.Prekey, state.Profile, unixSeconds)
}
