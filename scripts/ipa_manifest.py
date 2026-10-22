#!/usr/bin/env python3
"""Inspect IPA/.app metadata without extraction, execution or trust verification.

JSON includes file hashes, bundle metadata and Mach-O signature structure.
This is NOT a CMS/certificate trust, resource-seal or cryptographic verifier.
No input is copied; reports are written only with an explicit --output path.
"""

import argparse
import hashlib
import json
import os
import pathlib
import plistlib
import stat
import struct
import sys
import zipfile


THIN = {
    b"\xce\xfa\xed\xfe": ("<", False),
    b"\xcf\xfa\xed\xfe": ("<", True),
    b"\xfe\xed\xfa\xce": (">", False),
    b"\xfe\xed\xfa\xcf": (">", True),
}
FAT = {
    b"\xca\xfe\xba\xbe": (">", False),
    b"\xbe\xba\xfe\xca": ("<", False),
    b"\xca\xfe\xba\xbf": (">", True),
    b"\xbf\xba\xfe\xca": ("<", True),
}
SLOTS = {0: "CodeDirectory", 1: "Info", 2: "Requirements", 3: "Resources",
         4: "Application", 5: "Entitlements", 7: "DEREntitlements", 0x10000: "CMS"}
MAGICS = {0xFADE0CC0: "EmbeddedSignature", 0xFADE0C02: "CodeDirectory",
          0xFADE0C01: "Requirements", 0xFADE0C00: "Requirement",
          0xFADE7171: "Entitlements", 0xFADE7172: "DEREntitlements",
          0xFADE0B01: "BlobWrapper"}
HASHES = {1: ("sha1", 20), 2: ("sha256", 32), 3: ("sha256-truncated", 20),
          4: ("sha384", 48)}
INFO_KEYS = (
    "CFBundleIdentifier", "CFBundleExecutable", "CFBundleName", "CFBundleDisplayName",
    "CFBundleVersion", "CFBundleShortVersionString", "CFBundlePackageType",
    "MinimumOSVersion", "LSMinimumSystemVersion", "CFBundleSupportedPlatforms",
    "UIDeviceFamily", "UIFileSharingEnabled", "LSSupportsOpeningDocumentsInPlace",
    "DTPlatformName", "DTSDKName", "NSExtension", "UIBackgroundModes",
)
LIMITATION = (
    "Structural metadata only. No CMS verification, certificate trust evaluation, "
    "page/resource hash verification, provisioning-profile validation or installability claim."
)


class FormatError(ValueError):
    pass


def region(data, offset, length, label):
    if offset < 0 or length < 0 or offset > len(data) or length > len(data) - offset:
        raise FormatError(f"{label}: range {offset}+{length} exceeds {len(data)} bytes")
    return data[offset:offset + length]


def unpack(fmt, data, offset=0):
    return struct.unpack(fmt, region(data, offset, struct.calcsize(fmt), "structure"))


def cstring(data, offset, label):
    if not 0 < offset < len(data):
        raise FormatError(f"{label}: invalid string offset {offset}")
    end = data.find(b"\0", offset)
    if end < 0:
        raise FormatError(f"{label}: unterminated string")
    return data[offset:end].decode("utf-8", errors="replace")


def json_value(value):
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, dict):
        return {str(k): json_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_value(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def code_directory(blob):
    if len(blob) < 44:
        raise FormatError("CodeDirectory shorter than base header")
    magic, length, version, flags, hash_offset, ident_offset, special, slots, limit = unpack(
        ">9I", blob)
    hash_size, hash_type, platform, page_size = unpack(">4B", blob, 36)
    if length != len(blob) or magic != 0xFADE0C02:
        raise FormatError("Invalid CodeDirectory header")
    hash_info = HASHES.get(hash_type)
    # Validate slot ranges even though this inspector does not verify their hashes.
    if not hash_size:
        raise FormatError("CodeDirectory has zero-sized hashes")
    region(blob, hash_offset - special * hash_size, special * hash_size, "special hashes")
    region(blob, hash_offset, slots * hash_size, "code hashes")
    result = {
        "version": hex(version), "flags": hex(flags),
        "identifier": cstring(blob, ident_offset, "identifier"),
        "hash_type": hash_type, "hash_name": hash_info[0] if hash_info else "unknown",
        "hash_size": hash_size, "platform": platform,
        "page_size_exponent": page_size,
        "page_size_bytes": (1 << page_size) if 0 < page_size <= 31 else None,
        "special_slots": special, "code_slots": slots, "code_limit": limit,
        "hash_offset": hash_offset,
    }
    if version >= 0x20100:
        result["scatter_offset"] = unpack(">I", blob, 44)[0]
    if version >= 0x20200:
        team_offset = unpack(">I", blob, 48)[0]
        result["team_identifier"] = cstring(blob, team_offset, "team") if team_offset else None
    if version >= 0x20300:
        result["code_limit_64"] = unpack(">Q", blob, 56)[0]
    if version >= 0x20400:
        base, size, seg_flags = unpack(">3Q", blob, 64)
        result["executable_segment"] = {"base": base, "limit": size, "flags": hex(seg_flags)}
    if hash_info:
        algorithm = "sha256" if hash_type == 3 else hash_info[0]
        digest = hashlib.new(algorithm, blob).digest()
        result["directory_digest"] = digest.hex()
        result["cdhash"] = digest[:20].hex()
    return result


def signature(data):
    magic, length = unpack(">2I", data)
    blob = region(data, 0, length, "signature blob")
    result = {"magic": hex(magic), "format": MAGICS.get(magic, "unknown"),
              "length": length, "allocation_size": len(data), "slots": []}
    if magic == 0xFADE0C02:
        result["code_directory"] = code_directory(blob)
        return result
    if magic != 0xFADE0CC0:
        raise FormatError(f"Unsupported embedded signature magic {hex(magic)}")
    count = unpack(">I", blob, 8)[0]
    region(blob, 12, count * 8, "SuperBlob indices")
    for index in range(count):
        slot_type, offset = unpack(">2I", blob, 12 + 8 * index)
        if offset < 12 + count * 8:
            raise FormatError("Signature slot overlaps SuperBlob index")
        slot_magic, slot_length = unpack(">2I", blob, offset)
        if slot_length < 8:
            raise FormatError("Signature slot shorter than blob header")
        slot_blob = region(blob, offset, slot_length, "signature slot")
        name = SLOTS.get(slot_type)
        if name is None and 0x1000 <= slot_type <= 0x1005:
            name = f"AlternateCodeDirectory{slot_type - 0x1000}"
        slot = {"type": slot_type, "name": name or "unknown", "offset": offset,
                "magic": hex(slot_magic), "format": MAGICS.get(slot_magic, "unknown"),
                "length": slot_length, "sha256": hashlib.sha256(slot_blob).hexdigest()}
        if slot_magic == 0xFADE0C02:
            slot["code_directory"] = code_directory(slot_blob)
        elif slot_magic == 0xFADE7171:
            try:
                slot["entitlements"] = json_value(plistlib.loads(slot_blob[8:]))
            except Exception as error:
                slot["error"] = f"Cannot decode entitlement plist: {error}"
        elif slot_magic == 0xFADE7172:
            slot["payload_bytes"] = slot_length - 8
            slot["note"] = "DER entitlement payload inventoried; ASN.1 not decoded"
        elif slot_magic == 0xFADE0B01:
            slot["payload_bytes"] = slot_length - 8
            slot["note"] = "CMS payload inventoried; signature/trust not verified"
        result["slots"].append(slot)
    return result


def architecture(cpu, subtype):
    subtype &= 0x00FFFFFF
    if cpu == 0x0100000C:
        return "arm64e" if subtype == 2 else "arm64"
    if cpu == 0x0200000C:
        return "arm64_32"
    if cpu == 0x01000007:
        return "x86_64h" if subtype == 8 else "x86_64"
    if cpu == 7:
        return "i386"
    if cpu == 12:
        return {9: "armv7", 11: "armv7s", 12: "armv7k"}.get(subtype, "arm")
    return f"cpu-{hex(cpu)}-subtype-{subtype}"


def os_version(value):
    return f"{value >> 16}.{(value >> 8) & 255}.{value & 255}"


def thin_macho(data, slice_offset=0):
    magic = data[:4]
    if magic not in THIN:
        raise FormatError("Fat slice is not a supported Mach-O header")
    endian, is64 = THIN[magic]
    header_size = 32 if is64 else 28
    _, cpu, subtype, filetype, count, command_bytes, flags = unpack(endian + "7I", data)
    region(data, 0, header_size + command_bytes, "Mach-O load commands")
    result = {"architecture": architecture(cpu, subtype), "cpu_type": hex(cpu),
              "cpu_subtype": hex(subtype), "bits": 64 if is64 else 32,
              "endian": "little" if endian == "<" else "big",
              "slice_offset": slice_offset, "slice_size": len(data),
              "file_type": filetype, "flags": hex(flags),
              "code_signatures": [], "build_versions": []}
    offset = header_size
    for _ in range(count):
        cmd, size = unpack(endian + "2I", data, offset)
        if size < 8 or offset + size > header_size + command_bytes:
            raise FormatError("Invalid Mach-O load-command size")
        if cmd == 0x1D:  # LC_CODE_SIGNATURE, offsets are relative to this slice.
            if size < 16:
                raise FormatError("Short LC_CODE_SIGNATURE")
            start, length = unpack(endian + "2I", data, offset + 8)
            result["code_signatures"].append({"data_offset": start, "data_size": length,
                "metadata": signature(region(data, start, length, "LC_CODE_SIGNATURE data"))})
        elif cmd == 0x32:  # LC_BUILD_VERSION
            if size < 24:
                raise FormatError("Short LC_BUILD_VERSION")
            platform, minimum, sdk, tools = unpack(endian + "4I", data, offset + 8)
            if 24 + tools * 8 > size:
                raise FormatError("Invalid LC_BUILD_VERSION tool count")
            result["build_versions"].append({"platform": platform,
                "minimum_os": os_version(minimum), "sdk": os_version(sdk)})
        elif cmd in (0x24, 0x25, 0x2F, 0x30):
            if size < 16:
                raise FormatError("Short minimum-version command")
            minimum, sdk = unpack(endian + "2I", data, offset + 8)
            result["build_versions"].append({"legacy_command": hex(cmd),
                "minimum_os": os_version(minimum), "sdk": os_version(sdk)})
        offset += size
    if offset != header_size + command_bytes:
        raise FormatError("Load-command sizes do not match Mach-O header")
    result["has_code_signature"] = bool(result["code_signatures"])
    return result


def macho(data):
    if data[:4] in THIN:
        return {"format": "thin", "slices": [thin_macho(data)]}
    if data[:4] not in FAT:
        return None
    endian, is64 = FAT[data[:4]]
    count = unpack(endian + "I", data, 4)[0]
    entry_size = 32 if is64 else 20
    region(data, 8, count * entry_size, "fat architecture table")
    slices = []
    ranges = []
    for index in range(count):
        offset = 8 + index * entry_size
        if is64:
            cpu, subtype, start, size, alignment, reserved = unpack(endian + "2I2Q2I", data, offset)
        else:
            cpu, subtype, start, size, alignment = unpack(endian + "5I", data, offset)
        if start < 8 + count * entry_size or any(start < end and start + size > begin for begin, end in ranges):
            raise FormatError("Fat architecture overlaps table/another slice")
        ranges.append((start, start + size))
        entry = thin_macho(region(data, start, size, "fat slice"), start)
        if entry["cpu_type"] != hex(cpu) or entry["cpu_subtype"] != hex(subtype):
            raise FormatError("Fat table CPU metadata differs from slice header")
        slices.append(entry)
    if not slices:
        raise FormatError("Fat Mach-O has no architectures")
    return {"format": "fat64" if is64 else "fat", "slices": slices}


def safe_member_name(name):
    parts = pathlib.PurePosixPath(name).parts
    return bool(parts) and not name.startswith("/") and ".." not in parts and "\\" not in name


def inspect_file(name, size, mode, reader, maximum):
    record = {"path": name, "size": size, "mode": oct(mode & 0o7777),
              "kind": "symlink" if stat.S_ISLNK(mode) else "file"}
    digest = hashlib.sha256()
    head = b""
    with reader() as stream:
        while block := stream.read(1024 * 1024):
            if not head:
                head = block[:4]
            digest.update(block)
    record["sha256"] = digest.hexdigest()
    if record["kind"] == "symlink":
        return record, None
    is_plist = pathlib.PurePosixPath(name).name == "Info.plist"
    if not is_plist and head not in THIN and head not in FAT:
        return record, None
    if size > maximum:
        record["error"] = f"Metadata parse skipped: {size} bytes exceeds --max-file-bytes={maximum}"
        return record, None
    with reader() as stream:
        data = stream.read(maximum + 1)
    if len(data) != size:
        record["error"] = "File size changed or declared ZIP size disagrees with data"
        return record, None
    if is_plist:
        try:
            value = plistlib.loads(data)
            if not isinstance(value, dict):
                raise FormatError("Info.plist is not a dictionary")
            return record, value
        except Exception as error:
            record["error"] = f"Invalid Info.plist: {error}"
    else:
        try:
            record["macho"] = macho(data)
        except (FormatError, struct.error) as error:
            record["error"] = str(error)
    return record, None


def inspect(path, maximum):
    records, infos, warnings = [], [], []
    archive_hash = None
    if path.is_dir():
        if path.suffix.lower() != ".app":
            raise FormatError("Directory input must be an .app bundle")
        # Do not traverse symlinks, including bundle framework aliases.
        for directory, dirs, files in os.walk(path, followlinks=False):
            linked_dirs = [d for d in dirs if (pathlib.Path(directory) / d).is_symlink()]
            dirs[:] = sorted(d for d in dirs if d not in linked_dirs)
            for name in sorted(files + linked_dirs):
                file_path = pathlib.Path(directory) / name
                relative = path.name + "/" + file_path.relative_to(path).as_posix()
                metadata = file_path.lstat()
                if stat.S_ISLNK(metadata.st_mode):
                    target = os.fsencode(os.readlink(file_path))
                    records.append({"path": relative, "size": len(target),
                        "mode": oct(metadata.st_mode & 0o7777), "kind": "symlink",
                        "sha256": hashlib.sha256(target).hexdigest()})
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    warnings.append(f"Skipped non-regular entry: {relative}")
                    continue
                record, info = inspect_file(relative, metadata.st_size, metadata.st_mode,
                    lambda file_path=file_path: file_path.open("rb"), maximum)
                records.append(record)
                if info is not None:
                    infos.append((relative, info))
    else:
        with path.open("rb") as stream:
            archive_hash = hashlib.file_digest(stream, "sha256").hexdigest()
        with zipfile.ZipFile(path) as archive:
            seen = set()
            for item in archive.infolist():
                if item.filename in seen:
                    raise FormatError(f"Ambiguous duplicate ZIP member: {item.filename}")
                seen.add(item.filename)
                if not safe_member_name(item.filename):
                    raise FormatError(f"Unsafe ZIP member name: {item.filename!r}")
                if item.is_dir():
                    records.append({"path": item.filename, "size": 0, "kind": "directory"})
                    continue
                if item.flag_bits & 1:
                    raise FormatError(f"Encrypted ZIP member unsupported: {item.filename}")
                mode = item.external_attr >> 16
                record, info = inspect_file(item.filename, item.file_size, mode,
                    lambda item=item: archive.open(item), maximum)
                record["compressed_size"] = item.compress_size
                record["zip_crc32"] = f"{item.CRC:08x}"
                records.append(record)
                if info is not None:
                    infos.append((item.filename, info))
    bundles = []
    for name, info in infos:
        parent = pathlib.PurePosixPath(name).parent
        bundle = parent.parent if parent.name == "Contents" else parent
        if bundle.suffix.lower() not in (".app", ".appex", ".framework", ".bundle", ".xpc"):
            continue
        executable = info.get("CFBundleExecutable")
        base = parent / "MacOS" if parent.name == "Contents" else parent
        bundles.append({"path": str(bundle), "info_path": name,
            "fields": {key: json_value(info[key]) for key in INFO_KEYS if key in info},
            "executable_path": str(base / executable) if isinstance(executable, str) else None})
    errors = [{"path": record["path"], "error": record["error"]}
              for record in records if "error" in record]
    return {"schema_version": 1, "input_name": path.name,
        "input_kind": "app_directory" if path.is_dir() else "zip_archive",
        "archive_sha256": archive_hash, "limitations": LIMITATION,
        "files": sorted(records, key=lambda record: record["path"]),
        "bundles": sorted(bundles, key=lambda bundle: bundle["path"]),
        "warnings": warnings, "errors": errors}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=pathlib.Path, help="IPA ZIP or .app directory")
    parser.add_argument("--output", type=pathlib.Path, help="Explicit JSON report destination; default stdout")
    parser.add_argument("--max-file-bytes", type=int, default=256 * 1024 * 1024,
                        help="Maximum bytes loaded for individual Mach-O/plist parsing (hashes still stream)")
    args = parser.parse_args()
    if args.max_file_bytes <= 0:
        parser.error("--max-file-bytes must be positive")
    try:
        report = inspect(args.input, args.max_file_bytes)
        encoded = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
        if args.output:
            if args.output.resolve() == args.input.resolve():
                raise FormatError("Report destination must not overwrite input")
            if args.input.is_dir() and args.output.resolve().is_relative_to(args.input.resolve()):
                raise FormatError("Report destination must not modify input bundle")
            args.output.write_text(encoded, encoding="utf-8")
        else:
            sys.stdout.write(encoded)
        return 1 if report["errors"] else 0
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError, struct.error) as error:
        print(f"ipa_manifest: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
