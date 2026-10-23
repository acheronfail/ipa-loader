# Native iOS app and desktop bootstrap

The iOS app uses UIKit, with **Apps** and **Settings** tabs. `internal/iosapp`
owns account and operation state; `internal/iosnative` presents native controls,
Files, review and progress sheets. It shares Go authentication, signing and
device code with the desktop app. Fyne is used only by the desktop interface.

## Build

On macOS with Go and Xcode's iPhoneOS SDK:

```sh
just ios
just release macos
```

Both device payloads target arm64 and iOS 15+: `app/build/ios/IPA-Loader-Free-Accounts.ipa`
(uses external LocalDevVPN) and `app/build/ios/IPA-Loader-Paid-Accounts.ipa` (includes a
packet tunnel extension). Packaging embeds both in the desktop release. For
Linux and Windows, copy the Mac-built payloads into `app/build/ios/` before
packaging. Unbundled desktop runs can set `IPA_LOADER_IOS_IPA` to an absolute IPA
path. Build/version overrides are `IPA_LOADER_IOS_BUILD` and
`IPA_LOADER_IOS_VERSION`.

Bundle IDs are `org.ipaloader.desktop`, `org.ipaloader.ios`,
and `org.ipaloader.ios.tunnel`. Fixture apps use the same prefix.
Changing from the old IDs creates a separate application/container; it does not
migrate installed app data. Credential-store service names remain stable for
compatibility with saved desktop accounts.

## Setup

1. Connect an unlocked iPhone, establish Trust, then sign in and select the
   phone in the desktop app.
2. Choose **Set Up IPA Loader** and click its primary button. This task uses the
   packaged loader; **Install an IPA** uses a selected file. The desktop verifies the
   installation and transfers the original loader IPA and private setup
   credentials. Transfers are read back before the setup envelope is committed.
3. Open the iOS app. It validates the envelope, moves secrets into Keychain and
   removes the envelope from Documents. Sign in with the same Apple Account.
4. Use Wi-Fi. Paid developer teams receive the built-in VPN variant: allow its
   configuration using **Local VPN** in Settings and disconnect other VPNs.
   Free teams use [LocalDevVPN from the App Store](https://apps.apple.com/app/id6755608044)
   and its Device IP in Connection Settings (default `10.7.0.1`). Settings includes
   a **Get LocalDevVPN** link and hides the built-in VPN switch in this variant.
   The connection authenticates using the imported pairing record
   and pinned device certificate.

The desktop transfers pairing credentials and a signing key so the phone can
reuse the certificate. Passwords and desktop account sessions are not
transferred. These secrets are never embedded in release IPAs or progress logs.
Normal launches preserve renewed on-device identities.

If setup transfer is interrupted, close the phone app and repeat desktop setup.
Repeat setup after pairing becomes invalid. An expired loader must be
reinstalled from the desktop. Developer Mode, trust prompts, free-account app
limits and App ID allowances still apply.

## Apps and refresh

Apps remains readable when signed out. Rows show expiry, known installation
account and refresh history; tapping a row shows exact dates, team, version and
bundle ID. Refresh, Refresh All and import require sign-in and a connected local
VPN. The native VPN switch displays the actual connection status. Turning it off
prevents operations from implicitly reconnecting it.

**Refresh** stays in Apps and presents a progress sheet with optional Details.
**Refresh All** processes apps belonging to the current account and one of its
teams, with IPA Loader last. Results remain visible for each app. Unknown
accounts are not guessed from developer team identifiers.

Refresh first attempts to renew provisioning profiles without reinstalling:

- A verified signing binding must cover the installed app and all supported
  extensions, its original certificate, entitlements and embedded profiles.
- The account must still have the original certificate and matching App IDs.
  Downloaded profiles must authorize the same device, team, signer and signed
  entitlements, with sufficient remaining validity.
- Profiles already current produce no device writes or invented refresh date.
- New profiles are installed through misagent. Success requires independent
  profile readback and unchanged app inventory. Uncertain submissions remain
  errors; they never silently trigger another installation.
- Proven incompatibility or an explicit device rejection can use full signing
  instead. This uses the saved IPA, or asks the user to choose the original.
  Self-refresh uses the desktop-provided loader IPA. A full self-install may
  close the app; reopen it after SpringBoard finishes installing.

Installation/account/expiry history is accepted only while its installation
proof matches. Replacing the app invalidates receipts for older code. Older or
externally installed apps can show **Account unknown** until an authenticated
refresh verifies ownership. Unsupported nested provisioning graphs use full
signing rather than skipping their members.

## IPA storage

When re-signing an IPA, the loader keeps recognized optional capabilities only
when the new provisioning profile authorizes them. Installation Details lists
omitted capabilities; their related features (for example push notifications or
associated domains) may be unavailable. Push notifications use the environment
issued by the new profile. Unknown capabilities still produce an explicit error.
Identity and packet-tunnel permissions are validated separately. Paid accounts
use newly provisioned app groups and authorized keychain groups. Free accounts
use private app-local directories/preferences for app-group requests and map
keychain requests to the bundle's own authorized group. This permits installation
without App Groups support, but storage is not shared with other apps/extensions.

Both `PlugIns/` and ExtensionFoundation `Extensions/` bundles are supported.
App migration container identifiers are mapped to the installed app identifier;
if the extension's new profile does not authorize container access, that migration
extension is excluded from the installation. Other extensions remain included.
Free accounts omit the migration extension without registering an extra App ID.
Extension versions are aligned with the containing app before signing. Older
libraries containing 32-bit ARM and one arm64 slice are prepared using their
arm64 slice. All preparation changes affect the extracted working copy only.

Tap **+**, select an IPA in Files, review it, then install. **Keep IPA for
Refresh** is optional and off by default; the review shows its size. A retained
original is stored privately under `Library/Application Support/ipa-loader/apps`,
not Documents. Disabling retention removes a previous managed copy of that app
after a successful install. The user's source file remains untouched.

Confirmed installs clean up temporary extracted workspaces. Uncertain installs
retain the material needed to reconcile the submitted operation. Cancellation
before submission dismisses the sheet without presenting an error.

`Documents/IPALoader.ipa` is the separate loader fallback transferred during
desktop setup. It remains available for full self-refresh.

## Settings

Switch Account presents saved accounts, Add Another Account, Manage Accounts
and Sign Out in a native menu. Removing an account forgets its saved session;
it does not uninstall apps. Sign Out retains saved accounts for later use.
A single developer team is a read-only row; accounts with multiple teams get a
selector. Certificates show team/type and available dates, newest first, with
an explicit confirmation before revocation. App version/build appears in the
footer.

## Verification

From `app/`, using the repository's dependency caches when needed:

```sh
go test ./...
go test -race ./internal/iosapp ./internal/accounts ./internal/platform ./internal/ui
```

To exercise a local IPA through preparation, signing, verification and packaging
with synthetic paid/free profiles (no Apple account or device calls):

```sh
IPA_LOADER_TEST_IPA=/absolute/path/to/app.ipa go test ./internal/platform -run TestLocalIPACompatibility -v
```

This optional check needs Xcode's iPhoneOS SDK when the app needs a sharing
adapter. It verifies generated signatures/resources locally; it does not prove
Apple profile issuance, installation or app behavior on a device.

On macOS with a booted simulator:

```sh
sh app/scripts/test-ios-apps.sh <simulator-udid>
python3 scripts/verify_committed_fixtures.py
```

Omit the simulator ID to select an available iPhone simulator automatically;
the script boots and shuts it down if needed. CI runs this harness too.

The UIKit harness checks both connection variants' controls, guidance, row actions,
and LocalDevVPN App Store links, plus account/VPN gating, refresh without tab switching,
stable controls during repeated progress, review cancellation, optional IPA
retention, account menus, Details layout and rounded icons. Portable tests cover
profile validation/readback, fallback boundaries, history and account state.
