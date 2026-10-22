#!/usr/bin/env bash
set -euo pipefail

app="${1:?Usage: notarize-macos-release.sh app.app output.zip}"
output="${2:?Usage: notarize-macos-release.sh app.app output.zip}"
: "${APPLE_TEAM_ID:?Set the publishing Apple Team ID}"
[[ "$APPLE_TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] || { echo 'Invalid Apple Team ID.' >&2; exit 2; }
[[ -d "$app" && "$app" == *.app && "$output" == *.zip ]] || { echo 'Expected an app bundle and ZIP output.' >&2; exit 2; }
requirement="anchor apple generic and identifier \"org.ipaloader.desktop\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"$APPLE_TEAM_ID\""
codesign --verify --deep --strict --test-requirement "=$requirement" "$app"
umask 077
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/ipa-loader-notary.XXXXXX")"
archive=""
cleanup() {
    rm -rf "$work"
    if [[ -n "$archive" ]]; then rm -f "$archive"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

profile="${APPLE_NOTARY_KEYCHAIN_PROFILE:-ipa-loader-notary}"
authentication=(--keychain-profile "$profile")
if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
    : "${CODE_SIGN_KEYCHAIN:?CI notarization needs the disposable signing keychain}"
    : "${APPLE_NOTARY_APPLE_ID:?Set the Apple Account email secret}"
    : "${APPLE_NOTARY_PASSWORD:?Set the Apple app-specific password secret}"
    xcrun notarytool store-credentials "$profile" --keychain "$CODE_SIGN_KEYCHAIN" \
        --apple-id "$APPLE_NOTARY_APPLE_ID" --team-id "$APPLE_TEAM_ID" \
        --password "$APPLE_NOTARY_PASSWORD" >/dev/null
    authentication+=(--keychain "$CODE_SIGN_KEYCHAIN")
    unset APPLE_NOTARY_APPLE_ID APPLE_NOTARY_PASSWORD
fi

ditto -c -k --sequesterRsrc --keepParent "$app" "$work/upload.zip"
submit_status=0
xcrun notarytool submit "$work/upload.zip" "${authentication[@]}" \
    --wait --timeout 20m --output-format json > "$work/result.json" || submit_status=$?
# A transport error, timeout, malformed response or rejection never publishes a
# replacement archive. Preserve the submission ID so a timed-out job is traceable.
result="$(python3 - "$work/result.json" <<'PYTHON'
import json
import sys
import uuid
with open(sys.argv[1]) as stream:
    result = json.load(stream)
identifier, status = result.get('id', ''), result.get('status', '')
try:
    identifier = str(uuid.UUID(identifier))
except (ValueError, AttributeError, TypeError):
    raise SystemExit('Invalid notarization submission ID; no archive was published')
if status not in ('Accepted', 'Invalid', 'In Progress', 'Rejected'):
    raise SystemExit('Unexpected notarization response; no archive was published')
print(identifier, status)
PYTHON
)"
submission_id="${result%% *}"
status="${result#* }"
printf 'Notarization submission %s: %s\n' "$submission_id" "$status"
if [[ "$submit_status" != 0 || "$status" != Accepted ]]; then
    # Only completed rejections have a useful log. Keep it out of public release
    # assets; Xcode may include package paths and other implementation details.
    if [[ "$status" == Invalid || "$status" == Rejected ]]; then
        xcrun notarytool log "$submission_id" "${authentication[@]}" "$work/log.json" || true
        if [[ -f "$work/log.json" ]]; then
            python3 - "$work/log.json" <<'PYTHON'
import json
import sys
with open(sys.argv[1]) as stream:
    result = json.load(stream)
for issue in result.get('issues') or []:
    print('Notarization issue:', issue.get('code'), issue.get('message'))
PYTHON
        fi
    fi
    echo 'Notarization did not complete successfully; no archive was published.' >&2
    exit 1
fi
# Ticket delivery can fail transiently after Apple accepts the submission.
# Retry CloudKit lookup failures (68), without resubmitting or bypassing checks.
for action in staple validate; do
    for attempt in 1 2 3 4; do
        staple_status=0
        xcrun stapler "$action" "$app" || staple_status=$?
        if [[ "$staple_status" == 0 ]]; then break; fi
        if [[ "$staple_status" != 68 || "$attempt" == 4 ]]; then
            printf 'Stapler %s failed; no archive was published.\n' "$action" >&2
            exit "$staple_status"
        fi
        delay=$((attempt * 5))
        printf 'Ticket lookup failed; retrying stapler %s in %s seconds (attempt %s/4).\n' "$action" "$delay" "$((attempt + 1))" >&2
        sleep "$delay"
    done
done
codesign --verify --deep --strict --test-requirement "=$requirement" "$app"
spctl --assess --type execute --verbose=2 "$app"

# Staple the app, then rebuild the downloadable ZIP. The originally submitted
# ZIP cannot carry a stapled ticket itself. Replace the output only after checks.
archive="$(mktemp "$(dirname "$output")/.ipa-loader-notarized.XXXXXX")"
ditto -c -k --sequesterRsrc --keepParent "$app" "$archive"
unzip -tq "$archive"
mv -f "$archive" "$output"
archive=""
printf 'Notarized macOS app: %s\n' "$output"
