# Signature verification

`VerifyBundle` checks Mach-O signatures, code/resource hashes, nested code and
XML/DER entitlements. `VerifyBinary` checks a single executable or library.

Supply the expected certificate, identifier and entitlements. `AllowAdHoc` is
for fixture checks. Verification checks cryptographic integrity; certificate
trust, revocation and provisioning authorization require separate checks.

Unsupported signature formats and unsealed files fail closed.
