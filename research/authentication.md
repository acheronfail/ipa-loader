# Authentication findings

The investigated core uses SRP-6a with SHA-256, the RFC 5054 2048-bit group and
generator 2. The account password is transformed before SRP: `s2k` uses the raw
SHA-256 digest of its UTF-8 bytes as PBKDF2-HMAC-SHA256 input; `s2k_fo` uses the
lowercase hexadecimal digest bytes. The server supplies salt and iteration
count. The client must bound these parameters and reject unknown protocols.

The core's integer-returning hash helpers introduce an encoding distinction:
converting a salt or inner hash to an integer and back can remove leading zero
bytes. Its recovered exponent input is
`SHA256(minimumBE(salt_integer) || minimumBE(SHA256(":" || derived_password)_integer))`.
IPA Loader preserves salt and inner digest bytes, including leading zeros, in
`app/internal/apple/crypto.go`.

The client validates the SRP server public value and proof before accepting
session secrets. Subsequent encrypted SPD/application-token processing is
covered by the Go regression tests. Successful
password proof alone is not completion: account challenges and developer-token
issuance are separate stages. Session reuse must retain the required account
identity and authentication-provider binding, and must handle expiry explicitly.

Transport policy is endpoint-specific. Request construction, headers, redirect
handling, response limits, decompression and redaction belong to that policy;
sharing an authentication implementation does not justify forwarding credentials
to arbitrary hosts. The maintained implementation is in `app/internal/apple/`
and its shared application factory in `app/internal/authclient/`.
