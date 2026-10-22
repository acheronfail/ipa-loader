# Releases

Push an exact `vX.Y.Z` tag to run the release workflow. It tests the app, builds
the macOS app and iOS payloads, signs and notarizes macOS, then builds Linux and
Windows and creates a **draft** GitHub release. Reruns may update a draft but
cannot replace assets in an already published release. Normal `master` builds
run verification without signing credentials or Apple submissions.

## Shared macOS release Action

The workflow uses `dist-tools/actions/apple-release@v1`, which tracks compatible
v1 updates. Signing, temporary keychains, notarization, ticket retries and ZIP
packaging are maintained there. Use a version tag or full commit SHA in
`.github/workflows/ci.yml` to select a fixed release.

IPA Loader supplies its bundle ID, app/output paths and post-sign runtime audit.
The Action signs the outer app with hardened runtime and a timestamp without
recursively re-signing Resources. The embedded iOS IPAs and hashed sharing
adapter must remain byte-for-byte unchanged. Both iOS account variants still
pass production preflight before macOS signing.

Use a **Developer ID Application** certificate for direct downloads. Apple
Distribution and Mac Installer certificates serve different distribution paths.
The notarization API key authenticates with Apple; it does not replace or renew
the signing certificate.

## Configure credentials with the sync CLI

Keep the authoritative credential JSON in encrypted storage and supply it to the
`dist-tools` CLI through stdin. The source needs these fields for a team API key:

| Field | Purpose |
| --- | --- |
| `MACOS_CODE_SIGN_P12_BASE64` | Developer ID Application certificate and private key exported as PKCS12, base64 encoded |
| `MACOS_CODE_SIGN_P12_PASSWORD` | Password protecting that export |
| `APPLE_TEAM_ID` | Certificate's ten-character team ID |
| `APPLE_NOTARY_AUTH_MODE` | `api-team` |
| `APPLE_NOTARY_API_KEY` | App Store Connect `.p8` private key text |
| `APPLE_NOTARY_KEY_ID` | API key ID |
| `APPLE_NOTARY_ISSUER_ID` | Team key issuer UUID |

In the `dist-tools` checkout, put the target repository in an ignored local
allowlist and validate before writing:

```sh
credential-json-export | bin/dist-tools apple credentials inspect
credential-json-export | bin/dist-tools apple credentials sync \
  --config .local/repositories.json --repo OWNER/REPOSITORY --dry-run
credential-json-export | bin/dist-tools apple credentials sync \
  --config .local/repositories.json --repo OWNER/REPOSITORY
```

`credential-json-export` is a placeholder for your decrypted JSON export. No
password-manager integration is required. Do not commit the source, paste its
values into workflow YAML, or publish it as an artifact.

Sync validates the PKCS12 and selected auth mode before any writes, installs the
selected mode's secrets, installs a protected `APPLE_TEAM_ID` secret for log masking, and sets
`APPLE_TEAM_ID` and `APPLE_NOTARY_AUTH_MODE` compatibility/configuration variables. Review per-repository results and rerun after partial failures. The
workflow forwards only the selected mode's credentials, allowing older secrets
to remain available for rollback.

Individual API keys use `api-individual`, omit the issuer and require Xcode 26+.
The compatibility `apple-id` mode uses `APPLE_NOTARY_APPLE_ID` and
`APPLE_NOTARY_PASSWORD` (an app-specific password). A missing mode variable keeps
that legacy behavior. Prefer a dedicated API key for new setup.

Local `just release` produces an ad-hoc signed development package.

## Reliability and rollback

The shared Action submits once, waits for acceptance, and retries only transient
ticket lookups. It restores the runner keychain search list, bounds cleanup,
requires final signature/ticket/Gatekeeper checks, and creates the ZIP from the
stapled app. Failed signing/notarization does not replace a prior output ZIP.
The hosted-runner-only ticket networking workaround is enabled through an Action
input rather than duplicated in this repository.

Generic failure/retry tests live in `dist-tools`; this repository retains its
app-specific runtime and iOS preflight tests. Use the notarization submission ID
from the workflow to investigate a timeout before deciding to resubmit. Raw
notary logs are not release assets.

Retain the prior encrypted credential version and working Action SHA during
rotation. Restore that source with one sync and revert the Action reference if
needed. For the initial migration, reverting the migration restores the previous
local scripts/workflow. Older Apple Account secrets remain available; do not
revoke a valid predecessor certificate as a routine rotation step.
