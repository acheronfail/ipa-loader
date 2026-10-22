#!/bin/sh
# Run native app-list/authentication and both connection-variant UI checks.
set -eu
[ "$#" -le 1 ] || { echo "Usage: sh scripts/test-ios-apps.sh [booted-simulator-udid]" >&2; exit 1; }
boot_here=false
if [ "$#" -eq 0 ]; then
 selection=$(xcrun simctl list devices available --json | python3 -c '
import json, sys
phones = [d for group in json.load(sys.stdin)["devices"].values() for d in group if "iPhone" in d["name"]]
if not phones:
 raise SystemExit("No available iPhone simulator; install an iOS Simulator runtime in Xcode.")
phone = next((d for d in phones if d["state"] == "Booted"), phones[0])
print(phone["udid"], phone["state"])
')
 # simctl supplies a UUID and a single-word state.
 set -- $selection
 if [ "$2" != Booted ]; then boot_here=true; fi
 set -- "$1"
fi
app_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/ipa-apps-test.XXXXXX")
bundle="$test_root/AppsHarness.app"
identifier=org.ipaloader.apps-harness
cleanup() {
 xcrun simctl uninstall "$1" "$identifier" >/dev/null 2>&1 || true
 if [ "$boot_here" = true ]; then xcrun simctl shutdown "$1" >/dev/null 2>&1 || true; fi
 rm -rf "$test_root"
}
trap 'cleanup "$1"' EXIT
if [ "$boot_here" = true ]; then
 xcrun simctl boot "$1"
 xcrun simctl bootstatus "$1" -b
fi
mkdir -p "$bundle"
python3 - "$bundle/Info.plist" <<'PY'
import plistlib,sys
with open(sys.argv[1],"wb") as output:
 plistlib.dump(dict(CFBundleExecutable="apps-harness",CFBundleIdentifier="org.ipaloader.apps-harness",CFBundleName="Apps Harness",CFBundlePackageType="APPL",CFBundleVersion="1",CFBundleShortVersionString="1",LSRequiresIPhoneOS=True,MinimumOSVersion="15.0",UIDeviceFamily=[1,2],UILaunchScreen={}),output)
PY
sdk=$(xcrun --sdk iphonesimulator --show-sdk-path)
xcrun --sdk iphonesimulator clang -isysroot "$sdk" -arch "$(uname -m)" -mios-simulator-version-min=15.0 -fobjc-arc -framework UIKit -framework QuartzCore -framework Foundation -framework NetworkExtension "$app_root/internal/iosnative/tests/apps_harness.m" "$app_root/internal/iosnative/controls_ios.m" "$app_root/internal/iosnative/shell_ios.m" "$app_root/internal/iosnative/settings_ios.m" -o "$bundle/apps-harness"
codesign --force --sign - "$bundle"
xcrun simctl install "$1" "$bundle"
xcrun simctl launch --console "$1" "$identifier" >"$test_root/output" 2>&1
cat "$test_root/output"
grep -Fq "PASS: cancellation quietly dismisses the progress sheet" "$test_root/output"
for variant in builtin localdevvpn; do
 if [ "$variant" = localdevvpn ]; then
  xcrun simctl launch --console "$1" "$identifier" --connection-checks --localdevvpn >"$test_root/output" 2>&1
 else
  xcrun simctl launch --console "$1" "$identifier" --connection-checks >"$test_root/output" 2>&1
 fi
 cat "$test_root/output"
 grep -Eq "PASS: .* connection controls, copy, routing and App Store links" "$test_root/output"
done
