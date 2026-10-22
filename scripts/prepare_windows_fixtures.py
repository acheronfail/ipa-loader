#!/usr/bin/env python3
"""Prepare isolated Windows variants of committed, owned IPA fixtures.

All variants reuse one main identifier and one extension identifier, limiting
free-account portal/app quota consumption. Original inputs and Mach-O bytes
remain unchanged; signing and runtime injection belong to the application.
"""
import pathlib
import plistlib
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "fixtures" / "build" / "windows"
BUNDLE_ID = "org.ipaloader.windowsfixture"
INPUTS = {
    "baseline-v1": "ipa-loader-fixture-v1-unsigned.ipa",
    "baseline-v2": "ipa-loader-fixture-v2-unsigned.ipa",
    "framework": "ipa-loader-framework-v1-unsigned.ipa",
    "universal": "ipa-loader-framework-v3-universal.ipa",
    "extension": "ipa-loader-extension-v1-free-unsigned.ipa",
    "sharing": "ipa-loader-sharing-v12-adhoc.ipa",
}


def prepare(name, filename):
    source = ROOT / "fixtures" / "ipas" / filename
    target = OUTPUT / f"windows-{name}-unsigned.ipa"
    with zipfile.ZipFile(source) as original:
        main = [m for m in original.infolist()
                if m.filename.startswith("Payload/")
                and m.filename.count("/") == 2
                and m.filename.endswith(".app/Info.plist")]
        if len(main) != 1:
            raise ValueError("Expected exactly one main app")
        main_info = main[0].filename
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as package:
            for member in original.infolist():
                data = original.read(member)
                if member.filename == main_info:
                    info = plistlib.loads(data)
                    info.update(CFBundleIdentifier=BUNDLE_ID,
                                CFBundleDisplayName="Windows Test",
                                CFBundleName="Windows Test")
                    data = plistlib.dumps(info, fmt=plistlib.FMT_XML)
                elif member.filename.endswith(".appex/Info.plist"):
                    info = plistlib.loads(data)
                    info["CFBundleIdentifier"] = BUNDLE_ID + ".share"
                    data = plistlib.dumps(info, fmt=plistlib.FMT_XML)
                package.writestr(member, data)


if __name__ == "__main__":
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for variant, fixture in INPUTS.items():
        prepare(variant, fixture)
    print("Prepared six isolated Windows variants; committed inputs unchanged.")
