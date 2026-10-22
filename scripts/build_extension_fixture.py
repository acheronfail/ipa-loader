#!/usr/bin/env python3
"""Build an owned unsigned app with a basic Share extension; never install it."""
from pathlib import Path
import argparse
import hashlib
import plistlib
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("version", nargs="?", default="1")
parser.add_argument("--free-account", action="store_true", help="Use a separate owned ID to preserve paid-account fixture installs")
args = parser.parse_args()
version = args.version
variant = "-free" if args.free_account else ""
if not version.isdecimal() or not 1 <= int(version) <= 999:
    raise SystemExit("Use a fixture build number between 1 and 999")
output = ROOT / "fixtures/build" / f"extension-v{version}{variant}"
if output.exists():
    shutil.rmtree(output)
app = output / "Payload/ExtensionTest.app"
extension = app / "PlugIns/LoaderShare.appex"
extension.mkdir(parents=True)
sdk = subprocess.check_output(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True).strip()
common = ["xcrun", "--sdk", "iphoneos", "clang", "-target", "arm64-apple-ios15.0", "-isysroot", sdk,
    "-fobjc-arc", "-O2", "-Wall", "-Wextra", "-Wno-unused-parameter", "-framework", "UIKit", "-framework", "Foundation", "-Wl,-no_adhoc_codesign"]
source = ROOT / "fixtures/ios"
subprocess.run(common + [f'-DFIXTURE_VERSION="{version}"', str(source / "main-extension.m"), "-o", str(app / "ExtensionTest")], check=True)
subprocess.run(common + ["-fapplication-extension", str(source / "share-extension.m"), "-Wl,-e,_NSExtensionMain", "-o", str(extension / "LoaderShare")], check=True)
base = dict(CFBundleInfoDictionaryVersion="6.0", CFBundleShortVersionString=f"{version}.0", CFBundleVersion=version,
    MinimumOSVersion="15.0", CFBundleSupportedPlatforms=["iPhoneOS"], UIDeviceFamily=[1, 2])
main = dict(base, CFBundleIdentifier="org.ipaloader.extensiontest"+(".free" if args.free_account else ""), CFBundleExecutable="ExtensionTest",
    CFBundleName="ExtensionTest", CFBundleDisplayName="Extension Test", CFBundlePackageType="APPL", LSRequiresIPhoneOS=True, UILaunchScreen={})
child = dict(base, CFBundleIdentifier=main["CFBundleIdentifier"]+".share", CFBundleExecutable="LoaderShare",
    CFBundleName="LoaderShare", CFBundleDisplayName="IPA Loader Share", CFBundlePackageType="XPC!",
    NSExtension=dict(NSExtensionPointIdentifier="com.apple.share-services", NSExtensionPrincipalClass="LoaderShareController",
        NSExtensionAttributes=dict(NSExtensionActivationRule=dict(NSExtensionActivationSupportsText=True))))
(app / "Info.plist").write_bytes(plistlib.dumps(main))
(extension / "Info.plist").write_bytes(plistlib.dumps(child))
ipa = ROOT / "fixtures/build" / f"ipa-loader-extension-v{version}{variant}-unsigned.ipa"
with zipfile.ZipFile(ipa, "w", compression=zipfile.ZIP_DEFLATED) as z:
    for p in sorted(app.rglob("*")):
        if not p.is_file(): continue
        item = zipfile.ZipInfo(p.relative_to(output).as_posix(), (2020, 1, 1, 0, 0, 0))
        item.create_system = 3
        item.external_attr = (0o100755 if p.name in ("ExtensionTest", "LoaderShare") else 0o100644) << 16
        item.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(item, p.read_bytes())
print(f"{hashlib.sha256(ipa.read_bytes()).hexdigest()}  {ipa}")
