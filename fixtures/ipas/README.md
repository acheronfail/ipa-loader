# Portable fixture IPAs

Seven unsigned/ad-hoc inputs for baseline updates, frameworks, universal binaries,
extensions and shared storage. [manifest.json](manifest.json) records metadata,
checksums and rebuild commands; [sources](../ios/README.md) require Xcode.

Verify from the repository root:

```sh
python3 scripts/verify_committed_fixtures.py
```

Provision and sign inputs before installing. Use the same account/identity for
update-continuity checks. Sharing-adapter injection requires thin arm64 code.
