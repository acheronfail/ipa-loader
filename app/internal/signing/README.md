# Signing identities

Stores keys and CSRs using macOS Keychain, Windows DPAPI or Linux Secret Service.
Requests are persisted before submission; uncertain submissions are not retried
automatically. Certificate revocation requires explicit user confirmation.

`Tool.Sign` signs one code object and verifies its certificate, identifier,
entitlements and child signatures. See [signing findings](../../../research/signing.md)
for provisioning details.
