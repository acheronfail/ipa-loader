#!/bin/sh
# Build unsigned, deterministic IPA containers; never sign, execute or install.
set -eu
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fixture_output="$project_root/fixtures/build"
fixture_sdk=$(xcrun --sdk iphoneos --show-sdk-path)
mkdir -p "$fixture_output"

if [ "$#" -eq 0 ]; then
    set -- 1 2
fi
for fixture_version in "$@"; do
    case "$fixture_version" in
        1|2) fixture_source="$project_root/fixtures/ios/main.m" ;;
        *) echo "Unsupported fixture version: $fixture_version (choose 1 or 2)" >&2; exit 2 ;;
    esac
    fixture_app="$fixture_output/v$fixture_version/Payload/Fixture.app"
    mkdir -p "$fixture_app"
    xcrun --sdk iphoneos clang \
        -target arm64-apple-ios15.0 -isysroot "$fixture_sdk" \
        -fobjc-arc -O2 -Wall -Wextra -Wno-unused-parameter \
        -DFIXTURE_VERSION="\"$fixture_version\"" \
        -framework UIKit -framework Foundation \
        -Wl,-no_uuid -Wl,-no_adhoc_codesign \
        "$fixture_source" -o "$fixture_app/Fixture"

    python3 - "$fixture_app" "$fixture_version" "$fixture_output" <<'PY'
import hashlib
import pathlib
import plistlib
import struct
import sys
import zipfile

app, version, output = pathlib.Path(sys.argv[1]), sys.argv[2], pathlib.Path(sys.argv[3])
info = {
    "CFBundleDevelopmentRegion": "en",
    "CFBundleDisplayName": "IPA Loader Fixture",
    "CFBundleExecutable": "Fixture",
    "CFBundleIdentifier": "org.ipaloader.fixture",
    "CFBundleInfoDictionaryVersion": "6.0",
    "CFBundleName": "Fixture",
    "CFBundlePackageType": "APPL",
    "CFBundleShortVersionString": f"{version}.0",
    "CFBundleVersion": version,
    "LSRequiresIPhoneOS": True,
    "MinimumOSVersion": "15.0",
    "UIDeviceFamily": [1, 2],
    "UILaunchScreen": {},
    "UISupportedInterfaceOrientations": ["UIInterfaceOrientationPortrait"],
}
(app / "Info.plist").write_bytes(plistlib.dumps(info, sort_keys=True))

# Reject unexpected stale bundle contents rather than silently package them.
assert {p.name for p in app.iterdir()} == {"Fixture", "Info.plist"}
binary = (app / "Fixture").read_bytes()
magic, cpu, subtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from("<8I", binary)
assert magic == 0xFEEDFACF and cpu == 0x0100000C and filetype == 2
offset = 32
minimum_os = None
for _ in range(ncmds):
    cmd, size = struct.unpack_from("<II", binary, offset)
    assert size >= 8 and offset + size <= 32 + sizeofcmds
    assert cmd != 0x1D, "Unexpected LC_CODE_SIGNATURE in unsigned fixture"
    if cmd == 0x32:  # LC_BUILD_VERSION
        platform, minimum_os = struct.unpack_from("<II", binary, offset + 8)
        assert platform == 2, "Expected iOS device platform"
    offset += size
assert minimum_os == 15 << 16, "Expected iOS 15.0 deployment target"
assert offset == 32 + sizeofcmds

ipa = output / f"ipa-loader-fixture-v{version}-unsigned.ipa"
with zipfile.ZipFile(ipa, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for name in ("Fixture", "Info.plist"):
        item = zipfile.ZipInfo(f"Payload/Fixture.app/{name}", date_time=(2020, 1, 1, 0, 0, 0))
        item.create_system = 3
        item.external_attr = (0o100755 if name == "Fixture" else 0o100644) << 16
        item.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(item, (app / name).read_bytes(), compresslevel=9)
with zipfile.ZipFile(ipa) as archive:
    assert archive.testzip() is None
    assert archive.namelist() == ["Payload/Fixture.app/Fixture", "Payload/Fixture.app/Info.plist"]
    assert plistlib.loads(archive.read("Payload/Fixture.app/Info.plist")) == info
print(f"{hashlib.sha256(ipa.read_bytes()).hexdigest()}  {ipa}")
PY
done
