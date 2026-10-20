"""Reading a proof bundle, which is untrusted input, without letting it cost unbounded memory or time.

Before the zip library parses anything, the file's size and the entry count its end-of-central-directory record
declares are checked, so a file with millions of entries is refused without building a list of them. Then only the
five known entry names are accepted, once each, and each member's declared size is checked against its limit
before a byte is decompressed (the zip library stops at the declared size and fails the CRC if the data runs on,
so a header that lies cannot inflate past it). Nothing is extracted to disk, so names like `../x` or symbolic-link
entries cannot write or point anywhere: a member is only ever bytes in memory.

Limits (a real bundle of a large scan is a few MB): each data file 128 MiB, the manifest 1 MiB, the signature
4 KiB, all members together 256 MiB, the bundle file on disk 256 MiB."""

import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path

ALLOWED = ("manifest.json", "manifest.sig", "report.json", "evidence.jsonl", "audit.jsonl")
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_MEMBER_BYTES = {"manifest.json": 1024 * 1024, "manifest.sig": 4096}
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_BUNDLE_BYTES = 256 * 1024 * 1024
MAX_ENTRIES = 16  # five are expected; the count is read before the zip library lists them
_EOCD = b"PK\x05\x06"
_EOCD64_LOCATOR = b"PK\x06\x07"


class BundleError(Exception):
    """The file is not a well-formed bundle."""


@dataclass(frozen=True)
class RawBundle:
    files: dict[str, bytes]


def _declared_entries(path: Path) -> int:
    """The entry count in the end-of-central-directory record (ZIP64 aware), read from the last 64 KiB + 22 bytes
    without parsing the central directory."""
    size = path.stat().st_size
    with path.open("rb") as handle:
        tail_len = min(size, 65536 + 22)
        handle.seek(size - tail_len)
        tail = handle.read(tail_len)
    at = tail.rfind(_EOCD)
    if at < 0 or len(tail) - at < 22:
        raise BundleError("not a readable bundle: no end of central directory")
    entries = struct.unpack("<H", tail[at + 10 : at + 12])[0]
    locator = tail.rfind(_EOCD64_LOCATOR, 0, at)
    if entries == 0xFFFF or locator >= 0:
        # ZIP64: the real count is in the ZIP64 end record the locator points at; a bundle never needs ZIP64
        raise BundleError("not a readable bundle: ZIP64 archives are not used by bundles")
    return entries


def read_raw(path: str | Path) -> RawBundle:
    """Read a bundle defensively: bounded file size and entry count before parsing, only the five known entry
    names, no duplicates, bounded member sizes before decompressing. Nothing is extracted to disk."""
    target = Path(path)
    try:
        if not target.is_file():
            raise BundleError(f"not a readable bundle: {target} is not a file")
        if target.stat().st_size > MAX_BUNDLE_BYTES:
            raise BundleError(f"bundle is too large ({target.stat().st_size} bytes on disk; the limit is {MAX_BUNDLE_BYTES})")
        entries = _declared_entries(target)
    except OSError as exc:
        raise BundleError(f"not a readable bundle: {exc}") from exc
    if entries > MAX_ENTRIES:
        raise BundleError(f"bundle declares {entries} entries; a bundle has {len(ALLOWED)}")
    try:
        archive = zipfile.ZipFile(target)
    except (zipfile.BadZipFile, OSError, ValueError, EOFError) as exc:
        raise BundleError(f"not a readable bundle: {exc}") from exc
    try:
        with archive:
            infos = archive.infolist()
            if len(infos) > MAX_ENTRIES:
                raise BundleError(f"bundle has {len(infos)} entries; a bundle has {len(ALLOWED)}")
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise BundleError("duplicate entries in bundle")
            for name in names:
                if name not in ALLOWED:
                    raise BundleError(f"unexpected entry in bundle: {name!r}")
            missing = [name for name in ALLOWED if name not in names]
            if missing:
                raise BundleError(f"bundle is missing {missing}")
            declared = 0
            for info in infos:
                limit = MAX_MEMBER_BYTES.get(info.filename, MAX_FILE_BYTES)
                if info.file_size > limit:
                    raise BundleError(f"{info.filename} is too large ({info.file_size} bytes; the limit is {limit})")
                declared += info.file_size
            if declared > MAX_TOTAL_BYTES:
                raise BundleError(f"bundle is too large ({declared} bytes uncompressed; the limit is {MAX_TOTAL_BYTES})")
            files: dict[str, bytes] = {}
            for info in infos:
                limit = MAX_MEMBER_BYTES.get(info.filename, MAX_FILE_BYTES)
                with archive.open(info) as handle:
                    data = handle.read(limit + 1)
                if len(data) > limit:
                    raise BundleError(f"{info.filename} is too large")
                files[info.filename] = data
    except (zipfile.BadZipFile, RuntimeError, OSError, ValueError, EOFError, struct.error) as exc:
        raise BundleError(f"not a readable bundle: {exc}") from exc
    return RawBundle(files)
