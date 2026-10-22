# Anisette findings

The portable implementation reconstructs machine provisioning and MID/OTP
arithmetic in Go. Its network boundary is URL lookup, start provisioning (SPIM),
client response (CPIM), and finish response (PTM/TK). The arithmetic package
accepts those packets; the provider owns HTTP exchanges and persistent state.
No Apple library, cgo, emulator or remote anisette service executes inside
`app/internal/anisette/adimath`.

The portable state uses the recovered Android-format profile on all host
platforms. Android in API names identifies the format, not an OS restriction.
The start packet is 347 bytes and CPIM is 276 bytes. Finishing validates packet
shape/checksum, decrypts the 432-byte plaintext and checks all 32 nonce-binding
bytes before retaining the profile. The persisted state contains a 32-byte
normalized local key, 384-byte profile, 60-byte MID and environment. This is
secret reusable state; it is not a signing identity and is not interchangeable
with native macOS `adi.pb` or its 400-byte profile.

The packet checksum uses SHA-1 followed by a recovered transform of the first
16 digest bytes. Provisioning derives cipher representation from SPIM and the
matching finish key.
The OTP pipeline includes custom digest/expansion/message/body transformations
and emits a 28-byte frame. A signed 30-second time quotient is an input; that
alone does not identify the construction as standard TOTP or HMAC.

Fresh provisioning uses `crypto/rand` for local key, nonce, machine entropy, IV
and padding. Deterministic semantic-field entry points and the recovered native
PRNG model exist for differential tests. The production path does not use the
fixed clocks or seeds from those tests.

The macOS API investigation found that AOSKit marshals requests to the local
`com.apple.adid` service rather than computing the complete OTP in its public
Objective-C entry point. Native state and FairPlayIOKit interactions form a
separate integration boundary. Reproducing that disk/kernel integration is not
necessary for the portable engine.

Synthetic vectors in `adimath/testdata` cover arithmetic substages, packet
validation and end-to-end composition. The arithmetic translation is checked-in
source.
