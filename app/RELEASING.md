# Releases

Push an exact `vX.Y.Z` tag to run the release workflow. It tests the app, builds
the macOS app and iOS payloads, signs and notarizes macOS, then builds Linux and
Windows and creates a **draft** GitHub release. Reruns may update a draft but
cannot replace assets in an already published release. Normal `master` builds
run verification without accessing signing credentials or submitting to Apple.

## macOS signing credentials

Configure these repository Actions secrets:

| Secret | Value |
| --- | --- |
| `MACOS_CODE_SIGN_P12_BASE64` | Base64-encoded Developer ID Application certificate **and private key** exported as PKCS12 |
| `MACOS_CODE_SIGN_P12_PASSWORD` | Password protecting that export |
| `APPLE_NOTARY_APPLE_ID` | Apple Account email for the publishing team |
| `APPLE_NOTARY_PASSWORD` | An Apple app-specific password for that account |

Set the repository Actions variable `APPLE_TEAM_ID` to the certificate's ten
character team ID. The workflow fails early if any required value is missing;
there is no unsigned release fallback.

Use a **Developer ID Application** certificate for direct downloads. Apple
Distribution and Mac Installer certificates serve different distribution paths;
a self-signed certificate cannot be used for notarization. A Developer ID
certificate identifies the developer/team and can sign multiple apps.

To install an existing export without printing its secrets:

```sh
base64 -i /path/to/developer-id.p12 | gh secret set MACOS_CODE_SIGN_P12_BASE64 --repo acheronfail/ipa-loader
gh secret set MACOS_CODE_SIGN_P12_PASSWORD --repo acheronfail/ipa-loader < /path/to/export-password.txt
gh variable set APPLE_TEAM_ID --repo acheronfail/ipa-loader --body YOURTEAMID
gh secret set APPLE_NOTARY_APPLE_ID --repo acheronfail/ipa-loader
gh secret set APPLE_NOTARY_PASSWORD --repo acheronfail/ipa-loader
```

The last two commands prompt for values. Generate the app-specific password at
[Apple Account](https://account.apple.com/) under Sign-In and Security →
App-Specific Passwords. This is separate from the PKCS12 password and your normal
Apple Account password. Do not commit credential files or paste values into
workflow YAML. GitHub can list secret names but cannot retrieve secret values
from another repository.

## Reliability and verification

The build completes before credentials are imported into a disposable keychain
on the GitHub-hosted macOS runner. The signing wrapper selects exactly one valid
Developer ID Application identity matching `APPLE_TEAM_ID`, enables unattended
key access, and restores the original keychain search list on exit. Cleanup
commands have a 15-second timeout to avoid hanging during runner teardown.

The app is signed with a secure timestamp and hardened runtime. Signing does not
use `--deep`, preserving the embedded iOS payloads and hashed sharing adapter.
The runtime audit is repeated after signing. Notarization verifies the app's
identifier, Apple certificate chain and team before uploading.

The workflow carries over the fixes from `float-view-mobile`:

- On the disposable runner, block UDP 443 to force ticket delivery over TCP,
  working around [actions/runner-images#14924](https://github.com/actions/runner-images/issues/14924).
- Submit once, wait up to 20 minutes, and record Apple's submission ID. A timeout,
  transport error, malformed response or rejection fails the release.
- Retry only CloudKit lookup error 68 for both `stapler staple` and
  `stapler validate`, at most four attempts with delays of 5, 10 and 15 seconds.
  Retrying ticket retrieval never resubmits the app to Apple.
- Require ticket validation, signature verification and Gatekeeper assessment.
  Rebuild the ZIP from the stapled app, verify its integrity, and atomically
  replace the output only after every check passes. Only then upload assets.

Rejected submissions print Apple's issue codes and messages in the CI log.
Use the recorded ID with `xcrun notarytool log` to investigate. Notary logs and
credentials are not included in release assets. A submission still processing
after the timeout must not be treated as accepted; inspect its status before
deciding whether to rerun the job.

Run the mocked failure/retry regression tests locally with:

```sh
node --test scripts/macos-notarization.test.mjs
```

These tests exercise the shell scripts without contacting Apple or importing
identities. A real tagged CI run is needed to verify the configured credentials
and Apple's acceptance of the complete release bundle. Local `just release`
continues to produce an ad-hoc signed development package.

See Apple's [custom notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)
for service requirements and troubleshooting.
