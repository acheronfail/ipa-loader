#!/bin/sh
# Build an arm64 iPhone IPA without requiring Xcode account provisioning.
# The desktop app provisions and signs this package for the selected account.
set -eu
app_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$app_root"
[ "$(uname -s)" = Darwin ] || { echo 'Build the iOS payload on macOS with Xcode.' >&2; exit 1; }
export GOMODCACHE="$app_root/.cache/gomod" GOCACHE="$app_root/.cache/build" GOPATH="$app_root/.cache/gopath"
export CGO_ENABLED=1 GOOS=ios GOARCH=arm64
sdk=$(xcrun --sdk iphoneos --show-sdk-path)
export CC="$(xcrun --sdk iphoneos --find clang)"
export CGO_CFLAGS="-isysroot $sdk -arch arm64 -miphoneos-version-min=15.0"
export CGO_LDFLAGS="$CGO_CFLAGS"
host_arch=$(uname -m | sed 's/x86_64/amd64/')
host_sdk=$(xcrun --sdk macosx --show-sdk-path)
bundle="$app_root/build/ios/Payload/IPA Loader.app"
rm -rf "$bundle"
mkdir -p "$bundle"
go build -trimpath -ldflags '-s -w' -o "$bundle/ipa-loader" ./cmd/ipa-loader-ios
# Sharing adapter is prebuilt on the Mac; iOS never launches build tools.
env GOOS=darwin GOARCH="$(uname -m | sed 's/x86_64/amd64/')" CGO_CFLAGS= CGO_LDFLAGS= go run scripts/build-sharing-macos.go "$bundle/sharing-ios"
env GOOS=darwin GOARCH="$host_arch" CGO_CFLAGS="-isysroot $host_sdk" CGO_LDFLAGS="-isysroot $host_sdk" go run scripts/build-ios-icon.go "$bundle"
env GOOS=darwin GOARCH="$host_arch" CGO_ENABLED=0 go run ./cmd/licenses "$bundle/licenses"
python3 - "$bundle" <<'PY'
import plistlib,sys,zipfile,shutil,os,re
from pathlib import Path
p=Path(sys.argv[1])
with zipfile.ZipFile(p/'sharing-ios.zip','w',zipfile.ZIP_DEFLATED) as z:
 for member in sorted((p/'sharing-ios').rglob('*')):
  if member.is_file():z.write(member,member.relative_to(p/'sharing-ios'))
shutil.rmtree(p/'sharing-ios')
version=os.environ.get('IPA_LOADER_IOS_VERSION','0.1.0')
build=os.environ.get('IPA_LOADER_IOS_BUILD','16')
if not re.fullmatch(r'[0-9]+(?:\.[0-9]+){0,2}',build): raise SystemExit('Invalid IPA_LOADER_IOS_BUILD')
info=dict(CFBundleExecutable='ipa-loader',CFBundleIdentifier='org.ipaloader.ios',CFBundleName='IPA Loader',CFBundleDisplayName='IPA Loader',CFBundlePackageType='APPL',CFBundleShortVersionString=version,CFBundleVersion=build,MinimumOSVersion='15.0',LSRequiresIPhoneOS=True,UIDeviceFamily=[1,2],UIFileSharingEnabled=True,LSSupportsOpeningDocumentsInPlace=True,UILaunchScreen={},UISupportedInterfaceOrientations=['UIInterfaceOrientationPortrait','UIInterfaceOrientationLandscapeLeft','UIInterfaceOrientationLandscapeRight'],NSLocalNetworkUsageDescription='Connect to this iPhone through LocalDevVPN to install and refresh your apps.')
info['CFBundleIcons']={'CFBundlePrimaryIcon':{'CFBundleIconFiles':['AppIcon120','AppIcon180'],'UIPrerenderedIcon':False}}
info['CFBundleIcons~ipad']={'CFBundlePrimaryIcon':{'CFBundleIconFiles':['AppIcon152','AppIcon167'],'UIPrerenderedIcon':False}}
(p/'Info.plist').write_bytes(plistlib.dumps(info))
PY
codesign --force --sign - "$bundle"
python3 - "$app_root/build/ios" <<'PY'
from pathlib import Path
import sys,zipfile
root=Path(sys.argv[1])
target=root/'IPA-Loader.ipa'
with zipfile.ZipFile(target.with_suffix('.ipa.tmp'),'w',zipfile.ZIP_DEFLATED) as z:
 for p in sorted((root/'Payload').rglob('*')):
  if p.is_file():z.write(p,p.relative_to(root))
target.with_suffix('.ipa.tmp').replace(target)
print(target)
PY
# Paid-team variant: an independently provisioned packet tunnel extension.
vpn_root="$app_root/build/ios/vpn"
rm -rf "$vpn_root/Payload"
mkdir -p "$vpn_root/Payload"
cp -R "$bundle" "$vpn_root/Payload/"
vpn_bundle="$vpn_root/Payload/IPA Loader.app"
extension="$vpn_bundle/PlugIns/IPALoaderTunnel.appex"
mkdir -p "$extension"
"$CC" -isysroot "$sdk" -arch arm64 -miphoneos-version-min=15.0 -fobjc-arc -fapplication-extension -O2 -framework Foundation -framework NetworkExtension -Wl,-e,_NSExtensionMain ios/PacketTunnel/provider.m ios/PacketTunnel/reflect.c -o "$extension/IPALoaderTunnel"
python3 - "$vpn_bundle" "$extension" "$vpn_root" <<'PY'
from pathlib import Path
import plistlib,sys
app,ext,root=map(Path,sys.argv[1:])
info=plistlib.loads((app/'Info.plist').read_bytes())
info['NSLocalNetworkUsageDescription']='Connect to this iPhone to install and refresh your apps.'
(app/'Info.plist').write_bytes(plistlib.dumps(info))
(ext/'Info.plist').write_bytes(plistlib.dumps(dict(CFBundleExecutable='IPALoaderTunnel',CFBundleIdentifier=info['CFBundleIdentifier']+'.tunnel',CFBundleName='IPA Loader Tunnel',CFBundlePackageType='XPC!',CFBundleShortVersionString=info['CFBundleShortVersionString'],CFBundleVersion=info['CFBundleVersion'],MinimumOSVersion='15.0',NSExtension=dict(NSExtensionPointIdentifier='com.apple.networkextension.packet-tunnel',NSExtensionPrincipalClass='IPALoaderPacketTunnelProvider'))))
(root/'network-entitlements.plist').write_bytes(plistlib.dumps({'com.apple.developer.networking.networkextension':['packet-tunnel-provider']}))
PY
codesign --force --sign - --entitlements "$vpn_root/network-entitlements.plist" "$extension"
codesign --force --sign - --entitlements "$vpn_root/network-entitlements.plist" "$vpn_bundle"
python3 - "$vpn_root" "$app_root/build/ios/IPA-Loader-VPN.ipa" <<'PY'
from pathlib import Path
import sys,zipfile
root,target=map(Path,sys.argv[1:])
with zipfile.ZipFile(target.with_suffix('.ipa.tmp'),'w',zipfile.ZIP_DEFLATED) as z:
 for p in sorted((root/'Payload').rglob('*')):
  if p.is_file():z.write(p,p.relative_to(root))
target.with_suffix('.ipa.tmp').replace(target)
print(target)
PY
