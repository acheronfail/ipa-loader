#!/bin/sh
# Run native app-list/authentication behavior checks on an already booted simulator.
set -eu
[ "$#" -eq 1 ] || { echo "Usage: sh scripts/test-ios-apps.sh <booted-simulator-udid>" >&2; exit 1; }
app_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/ipa-apps-test.XXXXXX")
bundle="$test_root/AppsHarness.app"
identifier=org.ipaloader.apps-harness
cleanup() {
 xcrun simctl uninstall "$1" "$identifier" >/dev/null 2>&1 || true
 rm -rf "$test_root"
}
trap 'cleanup "$1"' EXIT
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
rg -q "PASS: cancellation quietly dismisses the progress sheet" "$test_root/output"
