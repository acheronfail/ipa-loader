# iOS signing

Go signing for arm64/arm64e Mach-O code and universal binaries. Writes SHA-256
CodeDirectories, XML/DER entitlements, resource seals and RSA/SHA-256 CMS.
Sign children before their containing bundle; verify with `codesignverify`.

Encrypted binaries, unsupported architectures and insufficient load-command space
are rejected. Input images are limited to 512 MiB.

The public certificate chain comes from zsign revision
`9299685bab7ef99827e06e5dfda93af747386590`; see
[its license](../../licenses/LICENSE.zsign).
