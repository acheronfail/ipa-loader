#!/bin/sh
# Builds a self-contained Go desktop app. No Python or global Go tools needed.
set -eu
app_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$app_root"
if [ "$(uname -s)" != Darwin ]; then
  echo 'This packaging script targets macOS.' >&2
  exit 1
fi
export GOMODCACHE="$app_root/.cache/gomod"
export GOCACHE="$app_root/.cache/build"
export GOPATH="$app_root/.cache/gopath"
export CGO_ENABLED=1
# Go adds -lobjc for each Objective-C package; allow repeated runtime linkage.
export CGO_LDFLAGS="${CGO_LDFLAGS:-} -Wl,-no_warn_duplicate_libraries"
bundle="$app_root/build/IPA Loader.app"
mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources"
go run scripts/build-sharing-macos.go "$bundle/Contents/Resources/sharing-macos"
if [ ! -f build/ios/IPA-Loader-Free-Accounts.ipa ] || [ ! -f build/ios/IPA-Loader-Paid-Accounts.ipa ]; then
  sh scripts/build-ios.sh
fi
rm -rf "$bundle/Contents/Resources/ios"
mkdir -p "$bundle/Contents/Resources/ios"
cp build/ios/IPA-Loader-Free-Accounts.ipa build/ios/IPA-Loader-Paid-Accounts.ipa "$bundle/Contents/Resources/ios/"
go build -trimpath -ldflags '-s -w' -o "$bundle/Contents/MacOS/ipa-loader" ./cmd/ipa-loader
go run ./cmd/icon "$app_root/build/AppIcon.iconset"
iconutil -c icns "$app_root/build/AppIcon.iconset" -o "$bundle/Contents/Resources/AppIcon.icns"
go run ./cmd/licenses "$bundle/Contents/Resources/licenses"
mkdir -p "$bundle/Contents/Resources/licenses/fishhook"
cp internal/platform/compat/LICENSE.fishhook "$bundle/Contents/Resources/licenses/fishhook/LICENSE"
# Signing, profile CMS and device TLS now use the shared Go implementation.
cat > "$bundle/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>ipa-loader</string>
<key>CFBundleIdentifier</key><string>org.ipaloader.desktop</string>
<key>CFBundleName</key><string>IPA Loader</string>
<key>CFBundleDisplayName</key><string>IPA Loader</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundleIconFile</key><string>AppIcon.icns</string>
<key>NSHighResolutionCapable</key><true/>
<key>LSMinimumSystemVersion</key><string>12.0</string>
<key>LSApplicationCategoryType</key><string>public.app-category.developer-tools</string>
</dict></plist>
PLIST
codesign --force --deep --sign - "$bundle"
codesign --verify --deep --strict "$bundle"
# Audit with developer tools unavailable, as on an end user's Mac.
env PATH=/usr/bin:/bin DEVELOPER_DIR=/nonexistent "$bundle/Contents/MacOS/ipa-loader" --check-runtime
/usr/bin/otool -L "$bundle/Contents/MacOS/ipa-loader" | /usr/bin/awk '
  NR > 1 && $1 !~ /^\/(System\/Library|usr\/lib)\// { print "Unexpected runtime library: " $1; failed = 1 }
  END { exit failed }
'
printf 'Built: %s\n' "$bundle"
