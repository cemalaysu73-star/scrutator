import zipfile
from dataclasses import dataclass
from pathlib import Path

ALLOWED = ("manifest.json", "manifest.sig", "report.json", "evidence.jsonl", "audit.jsonl")
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024


class BundleError(Exception):
    """The file is not a well-formed bundle."""


@dataclass(frozen=True)
class RawBundle:
    files: dict[str, bytes]


def read_raw(path: str | Path) -> RawBundle:
    """Read a bundle defensively: only the five known entry names, no duplicates, bounded
    sizes. Nothing is extracted to disk, so a hostile archive cannot write anywhere."""
    try:
        archive = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as exc:
        raise BundleError(f"not a readable bundle: {exc}") from exc
    try:
        with archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise BundleError("duplicate entries in bundle")
            for name in names:
                if name not in ALLOWED:
                    raise BundleError(f"unexpected entry in bundle: {name!r}")
            missing = [name for name in ALLOWED if name not in names]
            if missing:
                raise BundleError(f"bundle is missing {missing}")
            files: dict[str, bytes] = {}
            total = 0
            for info in infos:
                with archive.open(info) as handle:
                    data = handle.read(MAX_FILE_BYTES + 1)
                if len(data) > MAX_FILE_BYTES:
                    raise BundleError(f"{info.filename} is too large")
                total += len(data)
                if total > MAX_TOTAL_BYTES:
                    raise BundleError("bundle is too large")
                files[info.filename] = data
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        raise BundleError(f"not a readable bundle: {exc}") from exc
    return RawBundle(files)
