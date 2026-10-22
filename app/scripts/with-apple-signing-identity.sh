#!/bin/bash
set -euo pipefail

# Imports are confined to disposable hosted runners, never developer keychains.
if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted || "${RUNNER_OS:-}" != macOS ]]; then
    echo 'Signing identities may only be imported on a GitHub-hosted macOS runner.' >&2
    exit 1
fi
: "${APPLE_CODE_SIGN_P12_BASE64:?Add the signing PKCS12 to the protected Actions secrets}"
certificate_kind="Developer ID Application"
: "${APPLE_CODE_SIGN_P12_PASSWORD:?Add the PKCS12 password to GitHub Actions secrets}"
: "${APPLE_TEAM_ID:?Set APPLE_TEAM_ID to the publishing team}"
[[ "$APPLE_TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] || { echo 'Invalid Apple Team ID.' >&2; exit 2; }
[[ "$#" -gt 0 ]] || { echo "Usage: $0 command [arguments...]" >&2; exit 2; }
umask 077
working_directory="$(mktemp -d "$RUNNER_TEMP/ipa-loader-signing.XXXXXX")"
keychain_path="$working_directory/signing.keychain-db"
identity_path="$working_directory/identity.p12"
keychain_password="$(/usr/bin/openssl rand -hex 32)"
original_keychains=()
while read -r keychain; do
    keychain="${keychain#\"}"
    keychain="${keychain%\"}"
    original_keychains+=("$keychain")
done < <(security list-keychains -d user)

# Security services can stall during runner teardown. The hosted VM is discarded
# even if cleanup times out; no public certificate or custom trust is installed.
cleanup_command() {
    python3 - "$@" <<'PYTHON'
import subprocess
import sys
try:
    result = subprocess.run(sys.argv[1:], timeout=15, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode:
        print('::warning::CI keychain cleanup failed; the hosted runner will be discarded.')
except subprocess.TimeoutExpired:
    print('::warning::CI keychain cleanup timed out; the hosted runner will be discarded.')
PYTHON
}
cleanup() {
    if [[ "${#original_keychains[@]}" -gt 0 ]]; then
        cleanup_command security list-keychains -d user -s "${original_keychains[@]}" || true
    fi
    cleanup_command security delete-keychain "$keychain_path" || true
    rm -rf "$working_directory"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

python3 - "$identity_path" <<'PYTHON'
import base64
import os
import pathlib
import sys
encoded = ''.join(os.environ['APPLE_CODE_SIGN_P12_BASE64'].split())
pathlib.Path(sys.argv[1]).write_bytes(base64.b64decode(encoded, validate=True))
PYTHON
security create-keychain -p "$keychain_password" "$keychain_path"
security set-keychain-settings -lut 21600 "$keychain_path"
security unlock-keychain -p "$keychain_password" "$keychain_path"
security import "$identity_path" -k "$keychain_path" -f pkcs12 \
    -P "$APPLE_CODE_SIGN_P12_PASSWORD" -T /usr/bin/codesign >/dev/null
security set-key-partition-list -S apple-tool:,apple: -s -k "$keychain_password" "$keychain_path" >/dev/null
if [[ "${#original_keychains[@]}" -gt 0 ]]; then
    security list-keychains -d user -s "$keychain_path" "${original_keychains[@]}"
else
    security list-keychains -d user -s "$keychain_path"
fi
identities="$(security find-identity -v -p codesigning "$keychain_path")"
# Match the selected team rather than a developer's personal name or an arbitrary
# self-signed certificate. The signed app is also checked against Apple's chain.
matching="$(printf '%s\n' "$identities" | awk -v team="$APPLE_TEAM_ID" -v kind="$certificate_kind" \
    'index($0, "\"" kind ": ") && index($0, "(" team ")\"") {print $2}')"
identity_count="$(printf '%s\n' "$matching" | awk 'NF {count++} END {print count+0}')"
if [[ "$identity_count" != 1 ]]; then
    echo "Expected exactly one valid $certificate_kind identity for the selected team, found $identity_count." >&2
    exit 1
fi
CODE_SIGN_IDENTITY="$matching"
[[ "$CODE_SIGN_IDENTITY" =~ ^[A-F0-9]{40}$ ]]
CODE_SIGN_KEYCHAIN="$keychain_path"
export CODE_SIGN_IDENTITY CODE_SIGN_KEYCHAIN
unset APPLE_CODE_SIGN_P12_BASE64 APPLE_CODE_SIGN_P12_PASSWORD
"$@"
