#!/usr/bin/env bash
set -euo pipefail

app="${1:?Usage: sign-and-notarize-macos.sh app.app output.zip}"
output="${2:?Usage: sign-and-notarize-macos.sh app.app output.zip}"
: "${CODE_SIGN_IDENTITY:?Run through with-apple-signing-identity.sh}"
: "${CODE_SIGN_KEYCHAIN:?Run through with-apple-signing-identity.sh}"
: "${APPLE_TEAM_ID:?Set the publishing Apple Team ID}"
[[ "$CODE_SIGN_IDENTITY" =~ ^[A-F0-9]{40}$ ]] || { echo 'Expected a persistent signing identity SHA-1.' >&2; exit 2; }
[[ -d "$app" && "$app" == *.app && "$output" == *.zip ]] || { echo 'Expected an app bundle and ZIP output.' >&2; exit 2; }

# The app has one macOS executable. Do not use --deep to sign: the Resources
# directory also contains iOS payloads and a hashed iOS sharing adapter.
codesign --force --sign "$CODE_SIGN_IDENTITY" --keychain "$CODE_SIGN_KEYCHAIN" \
    --options runtime --timestamp "$app"
# Repeat the runtime audit with the hardened runtime enabled.
env PATH=/usr/bin:/bin DEVELOPER_DIR=/nonexistent "$app/Contents/MacOS/ipa-loader" --check-runtime
bash "$(dirname "$0")/notarize-macos-release.sh" "$app" "$output"
