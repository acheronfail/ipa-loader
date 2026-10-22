#!/usr/bin/env python3
"""Verify the curated portable input IPAs without signing, installing or extracting."""
import hashlib
import json
from pathlib import Path
import plistlib
import zipfile

from ipa_manifest import macho, safe_member_name

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "fixtures/ipas"


def verify():
    catalog = json.loads((DIRECTORY / "manifest.json").read_text())
    if catalog.get("format") != 1 or not catalog.get("fixtures"):
        raise ValueError("Invalid fixture catalog")
    names = set()
    total = 0
    for fixture in catalog["fixtures"]:
        name = fixture["file"]
        if Path(name).name != name or not name.endswith(".ipa") or name in names:
            raise ValueError("Invalid or duplicate fixture filename")
        names.add(name)
        path = DIRECTORY / name
        body = path.read_bytes()
        if len(body) != fixture["bytes"] or hashlib.sha256(body).hexdigest() != fixture["sha256"]:
            raise ValueError("Fixture checksum/size mismatch: " + name)
        total += len(body)
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len({entry.filename for entry in members}) != len(members):
                raise ValueError("Duplicate IPA member")
            if sum(entry.file_size for entry in members) > 4 << 20:
                raise ValueError("Curated fixture expanded beyond its review bound")
            roots = []
            for entry in members:
                if not safe_member_name(entry.filename) or entry.flag_bits & 1:
                    raise ValueError("Unsafe or encrypted IPA member")
                if entry.filename.lower().endswith((".mobileprovision", ".p12", ".pfx", ".pem", ".key", ".p8")):
                    raise ValueError("Provisioning/signing material cannot be committed")
                if entry.is_dir():
                    continue
                data = archive.read(entry)
                if b"-----BEGIN PRIVATE KEY-----" in data or b"-----BEGIN RSA PRIVATE KEY-----" in data:
                    raise ValueError("Private key marker in IPA")
                if entry.filename.startswith("Payload/") and entry.filename.count("/") == 2 and entry.filename.endswith("/Info.plist"):
                    roots.append(plistlib.loads(data))
                image = macho(data)
                if image is None:
                    continue
                for architecture in image["slices"]:
                    for signature in architecture["code_signatures"]:
                        metadata = signature["metadata"]
                        directories = [metadata["code_directory"]] if "code_directory" in metadata else []
                        for slot in metadata["slots"]:
                            if "code_directory" in slot:
                                directories.append(slot["code_directory"])
                            if slot["name"] == "CMS" and slot["length"] > 8:
                                raise ValueError("Developer CMS signatures cannot be committed")
                        if not directories or any(not int(directory["flags"], 16) & 2 for directory in directories):
                            raise ValueError("Only unsigned or ad-hoc code is allowed")
            if len(roots) != 1:
                raise ValueError("Expected one main app")
            info = roots[0]
            for field, expected in (("CFBundleIdentifier", "bundle_id"), ("CFBundleShortVersionString", "version"), ("CFBundleVersion", "build")):
                if info[field] != fixture[expected]:
                    raise ValueError("Fixture metadata mismatch")
        print("Verified " + name)
    if names != {path.name for path in DIRECTORY.glob("*.ipa")}:
        raise ValueError("Uncatalogued fixture IPA")
    print(f"{len(names)} input IPAs verified ({total:,} bytes); no profiles or developer CMS signatures")


if __name__ == "__main__":
    verify()
