# Provisioning and signing findings

Registration identity and installed bundle identity are distinct. The
investigated core constructs an authorization identifier by appending a dot and
team identifier to the original bundle ID; the recovered operation is direct
concatenation, not a hash suffix. Later policy may restore the original installed
identifier. IPA Loader registers/reuses the suffixed identifier, uses returned
profile constraints to choose the installed ID, and preserves the original in
`ALTBundleIdentifier` for free provisioning. Ambiguous or cross-team replacements
must be rejected rather than resolved by guessing an identifier.

Portal App-ID record IDs are opaque and differ from bundle identifier strings.
The profile retrieval request uses that record ID. A download-like action name
does not prove the request is read-only: profile generation/update can be
server-managed. Certificate/profile response encoding also matters: plist data
fields are already binary, while JSON API certificate-content strings may be
Base64. Do not decode both forms identically.

A usable signing identity requires a matching private key, public certificate
and active portal record. Issuance success alone is insufficient. Retain the
locally generated key before relying on a CSR operation; confirm downloaded
certificate public-key equality. Listing a certificate cannot recover its key.
Certificate quota failures must not silently revoke unrelated identities.

Before signing, validate profile expiry, platform, device authorization,
certificate inclusion, team/prefix relationship and entitlements. An embedded
plist extracted from a CMS profile does not by itself establish certificate
trust or authorization. Free/paid account labels also do not replace profile
validation.

The static signing recovery established big-endian CodeDirectory serialization,
4 KiB code-page hashing, descending special slots and final-header-before-hash
ordering. A final partial page is hashed at its actual length. Special hashes
cover Info.plist, requirements, CodeResources and XML/DER entitlement blobs as
applicable. The observed native producer's fixed header layout is a property of
that producer, not a universal CodeDirectory rule.

IPA Loader's maintained writer uses SHA-256 CodeDirectories and detached
RSA/SHA-256 CMS with both Apple hash-agility attributes. It signs contained code
inside out and independently verifies code pages, resources and entitlements.
Its supported graph covers 64-bit iPhone main apps, frameworks/dylibs and basic
app extensions. Universal slices must agree on entitlements; frameworks/dylibs
do not receive app entitlements. See the implementation boundaries in
[the signer](../app/internal/gosign/README.md) and
[the verifier](../app/internal/codesignverify/README.md).

App groups and shared keychain need per-bundle provisioning and validated
profile authorization. The compatibility adapter maps supported Foundation and
SecItem operations. Unsupported graphs,
capabilities and encrypted/simulator/legacy slices fail before portal mutations.

Public Apple trust certificates and the upstream attribution they require are
kept with source. Fixture checks verify structure and cryptographic consistency.
