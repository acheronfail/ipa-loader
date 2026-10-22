#!/usr/bin/env python3
"""Build an owned unsigned iOS app -> framework -> dylib fixture, without installing."""
import hashlib
import argparse
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("version", nargs="?", default="1")
parser.add_argument("--universal", action="store_true", help="Build both arm64 and arm64e slices")
args = parser.parse_args()
version = args.version
if not version.isdecimal() or not 1 <= int(version) <= 999:
    raise SystemExit("Use a fixture build number between 1 and 999")
variant = "universal" if args.universal else "unsigned"
output = ROOT / "fixtures/build" / f"framework-v{version}-{variant}"
if output.exists():
    shutil.rmtree(output)
app = output / "Payload/FrameworkTest.app"
frameworks = app / "Frameworks"
kit = frameworks / "FixtureKit.framework"
kit.mkdir(parents=True)
sdk = subprocess.check_output(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True).strip()
common = ["xcrun", "--sdk", "iphoneos", "clang",
          "-isysroot", sdk, "-O2", "-Wall", "-Wextra", "-Wno-unused-parameter",
          "-Wl,-no_adhoc_codesign"]
source = ROOT / "fixtures/ios"
def compile_binary(flags, destination):
    slices = []
    for arch in (["arm64", "arm64e"] if args.universal else ["arm64"]):
        binary = output / "slices" / arch / destination.name
        binary.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(common + ["-target", f"{arch}-apple-ios15.0"] + flags + ["-o", str(binary)], check=True)
        slices.append(str(binary))
    if args.universal:
        subprocess.run(["xcrun", "lipo", "-create", *slices, "-output", str(destination)], check=True)
    else:
        shutil.copy2(slices[0], destination)

compile_binary(["-dynamiclib", str(source / "framework-math.c"),
    "-Wl,-install_name,@rpath/libFixtureMath.dylib"], frameworks / "libFixtureMath.dylib")
compile_binary(["-dynamiclib", "-fobjc-arc", str(source / "framework-kit.m"),
    "-framework", "Foundation", "-L" + str(frameworks), "-lFixtureMath",
    "-Wl,-install_name,@rpath/FixtureKit.framework/FixtureKit"], kit / "FixtureKit")
compile_binary(["-fobjc-arc", f'-DFIXTURE_VERSION="{version}"', str(source / "main-framework.m"),
    "-framework", "UIKit", "-framework", "Foundation", "-F" + str(frameworks), "-framework", "FixtureKit",
    "-Wl,-rpath,@executable_path/Frameworks"], app / "FrameworkTest")
info = dict(CFBundleIdentifier="org.ipaloader.frameworktest", CFBundleExecutable="FrameworkTest",
    CFBundleName="FrameworkTest", CFBundleDisplayName="Framework Test", CFBundlePackageType="APPL",
    CFBundleShortVersionString=f"{version}.0", CFBundleVersion=version, MinimumOSVersion="15.0",
    CFBundleInfoDictionaryVersion="6.0", LSRequiresIPhoneOS=True, UIDeviceFamily=[1, 2], UILaunchScreen={})
(app / "Info.plist").write_bytes(plistlib.dumps(info))
(kit / "Info.plist").write_bytes(plistlib.dumps(dict(CFBundleIdentifier="org.ipaloader.FixtureKit",
    CFBundleExecutable="FixtureKit", CFBundleName="FixtureKit", CFBundlePackageType="FMWK",
    CFBundleInfoDictionaryVersion="6.0", CFBundleShortVersionString="1.0", CFBundleVersion="1",
    MinimumOSVersion="15.0", CFBundleSupportedPlatforms=["iPhoneOS"])))
(kit / "proof.txt").write_text("framework-resource-ok\n")
ipa = ROOT / "fixtures/build" / f"ipa-loader-framework-v{version}-{variant}.ipa"
with zipfile.ZipFile(ipa, "w", compression=zipfile.ZIP_DEFLATED) as z:
    for p in sorted(app.rglob("*")):
        if not p.is_file():
            continue
        item = zipfile.ZipInfo(p.relative_to(output).as_posix(), (2020, 1, 1, 0, 0, 0))
        item.create_system = 3
        mode = 0o100755 if p.name in ("FrameworkTest", "FixtureKit", "libFixtureMath.dylib") else 0o100644
        item.external_attr = mode << 16
        item.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(item, p.read_bytes())
print(f"{hashlib.sha256(ipa.read_bytes()).hexdigest()}  {ipa}")
