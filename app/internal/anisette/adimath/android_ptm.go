package adimath

import "errors"

// DecryptAndroidPTM decrypts the ciphertext blocks in an Android PTM response.
// session is the common CBC context derived from the matching SPIM, tk is the
// 16-byte response value, and iv is PTM[4:20]. Framing, authentication and
// validation of decrypted fields are separate. The same arithmetic also matches
// the captured Mac PTM when supplied its matching session context.
func DecryptAndroidPTM(session *CBCContext, tk, iv [16]byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%16 != 0 {
		return nil, errors.New("PTM ciphertext length must be a multiple of 16")
	}
	encryptedTK := EncryptCBCBlock(session, tk, [16]byte{})
	ctx := newAndroidPTMContextFromEncryptedTK(encryptedTK)
	previous := iv
	plaintext := make([]byte, len(ciphertext))
	for off := 0; off < len(ciphertext); off += 16 {
		var input [16]byte
		copy(input[:], ciphertext[off:off+16])
		block := decryptAndroidPTMBlock(&ctx, input)
		for i := range block {
			plaintext[off+i] = block[i] ^ previous[i]
		}
		previous = input
	}
	return plaintext, nil
}
