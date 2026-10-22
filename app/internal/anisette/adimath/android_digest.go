package adimath

// TransformAndroidDigest16 applies the recovered Android PTM-checksum wire transform to the
// first 16 bytes of a SHA1 digest. The remaining four SHA1 bytes pass through
// unchanged in the observed 20-byte checksum field.
func TransformAndroidDigest16(digest [16]byte) [16]byte {
	return TransformAndroidChecksumBlock(EncodeAndroidDigest16(digest))
}
