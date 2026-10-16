"""Load, validate, merge and query knowledge packs.

The bundled packs ship inside the wheel (`scrutator/packs/data`). A user pack directory can add
entries or replace bundled ones by `id`; nothing in Python changes. The merged result is a
`PackSet`, which can describe itself as a dictionary: reports embed that dictionary, so a
verifier can recompute every pack-driven result from the report alone.
"""

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from functools import cached_property
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from scrutator.packs.schema import ENTRY_MODELS, FILE_MODELS, KINDS, ProviderEntry, SignalEntry, TakeoverEntry

MANIFEST = "manifest.json"


class PackError(ValueError):
    """A pack file, manifest or pack dictionary is invalid. The message lists every problem."""


def bundled_dir():
    """The directory of packs shipped with Scrutator (a pathlib Path in a normal install)."""
    return resources.files("scrutator.packs").joinpath("data")


def file_digest(data: bytes) -> str:
    """sha256 of a pack file with line endings normalised, so a checkout that converted LF to
    CRLF (Windows with autocrlf) still matches the manifest."""
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def _dump(entry) -> dict:
    return entry.model_dump(mode="json")


def _errors(filename: str, exc: ValidationError) -> list[str]:
    out = []
    for item in exc.errors():
        where = ".".join(str(part) for part in item["loc"])
        out.append(f"{filename}: {where}: {item['msg']}")
    return out


@dataclass(frozen=True)
class PackFileInfo:
    name: str
    kind: str
    version: str
    origin: str  # "bundled" or "user"
    entries: int
    content_sha256: str

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "version": self.version,
            "origin": self.origin,
            "entries": self.entries,
            "content_sha256": self.content_sha256,
        }


def parse_file(name: str, data: bytes, origin: str) -> tuple[PackFileInfo, tuple]:
    """Validate one pack file. Returns its description and its entries; raises PackError."""
    try:
        document = yaml.safe_load(data.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise PackError(f"{name}: not readable YAML: {exc}") from exc
    if not isinstance(document, dict):
        raise PackError(f"{name}: a pack file must be a mapping")
    kind = document.get("kind")
    if kind not in FILE_MODELS:
        raise PackError(f"{name}: kind must be one of {list(KINDS)}, not {kind!r}")
    try:
        parsed = FILE_MODELS[kind].model_validate(document)
    except ValidationError as exc:
        raise PackError("\n".join(_errors(name, exc))) from exc
    seen: set[str] = set()
    duplicates = []
    for entry in parsed.entries:
        if entry.id in seen:
            duplicates.append(entry.id)
        seen.add(entry.id)
    if duplicates:
        raise PackError(f"{name}: duplicate ids: {sorted(set(duplicates))}")
    content = {"kind": kind, "version": parsed.version, "entries": [_dump(e) for e in parsed.entries]}
    info = PackFileInfo(name, kind, parsed.version, origin, len(parsed.entries), _sha(content))
    return info, tuple(parsed.entries)


def build_manifest(directory) -> dict:
    """The manifest for a pack directory: the digest of every YAML file in it."""
    files = {
        item.name: file_digest(item.read_bytes())
        for item in sorted(directory.iterdir(), key=lambda p: p.name)
        if item.is_file() and item.name.endswith((".yaml", ".yml"))
    }
    return {"schema": 1, "files": files}


def _check_manifest(directory, names: list[str], required: bool) -> list[str]:
    manifest_path = directory.joinpath(MANIFEST)
    if not manifest_path.is_file():
        return [f"{MANIFEST} is missing"] if required else []
    try:
        manifest = json.loads(manifest_path.read_bytes())
        declared = manifest["files"]
        if not isinstance(declared, dict):
            raise TypeError("files is not an object")
    except (ValueError, KeyError, TypeError) as exc:
        return [f"{MANIFEST} is not a valid manifest: {exc}"]
    problems = []
    for name in names:
        if name not in declared:
            problems.append(f"{name} is not listed in {MANIFEST}")
        elif declared[name] != file_digest(directory.joinpath(name).read_bytes()):
            problems.append(f"{name} does not match its sha256 in {MANIFEST}")
    for name in declared:
        if name not in names:
            problems.append(f"{MANIFEST} lists {name}, which is not in the directory")
    return problems


def read_dir(directory, origin: str) -> list[tuple[PackFileInfo, tuple]]:
    """Every pack file in a directory, validated. All problems are reported together."""
    if not directory.is_dir():
        raise PackError(f"{directory} is not a directory")
    names = sorted(item.name for item in directory.iterdir() if item.is_file() and item.name.endswith((".yaml", ".yml")))
    problems = _check_manifest(directory, names, required=origin == "bundled")
    loaded = []
    for name in names:
        try:
            loaded.append(parse_file(name, directory.joinpath(name).read_bytes(), origin))
        except PackError as exc:
            problems.append(str(exc))
    if problems:
        raise PackError("\n".join(problems))
    return loaded


def validate_dir(directory=None) -> list[str]:
    """The problems found in a pack directory (the bundled one by default); empty means valid."""
    target = bundled_dir() if directory is None else Path(directory)
    try:
        read_dir(target, "bundled" if directory is None else "user")
    except PackError as exc:
        return str(exc).splitlines()
    return []


class PackSet:
    """The merged content of the bundled packs and any user packs, with matching helpers."""

    def __init__(self, files: Sequence[dict], providers=(), takeover=(), signals=()) -> None:
        self.files = tuple(files)
        self.providers: tuple[ProviderEntry, ...] = tuple(sorted(providers, key=lambda e: e.id))
        self.takeover: tuple[TakeoverEntry, ...] = tuple(sorted(takeover, key=lambda e: e.id))
        self.signals: tuple[SignalEntry, ...] = tuple(sorted(signals, key=lambda e: e.id))

    # description

    def effective(self) -> dict:
        return {
            "providers": [_dump(e) for e in self.providers],
            "takeover": [_dump(e) for e in self.takeover],
            "signals": [_dump(e) for e in self.signals],
        }

    @property
    def effective_sha256(self) -> str:
        return _sha(self.effective())

    def to_dict(self) -> dict:
        return {"files": list(self.files), "effective": self.effective(), "effective_sha256": self.effective_sha256}

    @classmethod
    def from_dict(cls, data: Any) -> "PackSet":
        """Rebuild a PackSet from `to_dict()` output, validating every entry again."""
        if not isinstance(data, dict) or not isinstance(data.get("effective"), dict) or not isinstance(data.get("files"), list):
            raise PackError("pack description is malformed")
        problems = []
        parsed: dict[str, list] = {}
        for kind in KINDS:
            items = data["effective"].get(kind, [])
            if not isinstance(items, list):
                problems.append(f"effective.{kind} is not a list")
                continue
            parsed[kind] = []
            for index, item in enumerate(items):
                try:
                    parsed[kind].append(ENTRY_MODELS[kind].model_validate(item))
                except ValidationError as exc:
                    problems.extend(_errors(f"effective.{kind}[{index}]", exc))
        if problems:
            raise PackError("\n".join(problems[:10]))
        return cls(data["files"], parsed["providers"], parsed["takeover"], parsed["signals"])

    # matching

    @cached_property
    def _host_rules(self) -> dict[tuple[str, str], list[tuple[int, str, re.Pattern, Any]]]:
        rules: dict[tuple[str, str], list] = {}

        def add(table: str, kind: str, patterns, entry) -> None:
            for pattern in patterns:
                regex = re.compile(r"(?:^|\.)" + re.escape(pattern).replace(r"\*", "[a-z0-9_-]*") + "$")
                rules.setdefault((table, kind), []).append((len(pattern.replace("*", "")), entry.id, regex, entry))

        for entry in self.providers:
            for kind in ("ns", "mx", "spf", "cname"):
                add("providers", kind, getattr(entry, kind), entry)
        for entry in self.takeover:
            add("takeover", "cname", entry.cname, entry)
        return rules

    def _best(self, table: str, kind: str, host: str):
        host = str(host).strip().lower().rstrip(".")
        best = None
        for specificity, entry_id, regex, entry in self._host_rules.get((table, kind), []):
            if regex.search(host) and (best is None or (-specificity, entry_id) < (-best[0], best[1])):
                best = (specificity, entry_id, entry)
        return best[2] if best else None

    def match_provider(self, kind: str, value: str) -> ProviderEntry | None:
        """The provider entry for a name server (`ns`), mail exchanger (`mx`), SPF include
        (`spf`), CNAME target (`cname`), AS number (`asn`, "AS13335" or 13335) or certificate
        issuer string (`issuer`). The most specific pattern wins; ties go to the lower id."""
        if kind == "asn":
            digits = re.sub(r"(?i)^as", "", str(value).strip())
            if not digits.isdigit():
                return None
            number = int(digits)
            hits = [e for e in self.providers if number in e.asn]
            return min(hits, key=lambda e: e.id) if hits else None
        if kind == "issuer":
            text = " ".join(str(value).lower().split())
            best = None
            for entry in self.providers:
                for pattern in entry.issuer:
                    if pattern in text and (best is None or (-len(pattern), entry.id) < (-best[0], best[1].id)):
                        best = (len(pattern), entry)
            return best[1] if best else None
        return self._best("providers", kind, value)

    def match_takeover(self, host: str) -> TakeoverEntry | None:
        """The takeover fingerprint whose CNAME suffix matches `host`, if any."""
        return self._best("takeover", "cname", host)


def load_packs(extra_dirs: Sequence[Path] = (), *, bundled=True) -> PackSet:
    """The bundled packs plus any user directories, merged by entry id (later wins)."""
    sources = [(bundled_dir(), "bundled")] if bundled else []
    sources += [(Path(d), "user") for d in extra_dirs]
    infos: list[dict] = []
    merged: dict[str, dict[str, Any]] = {kind: {} for kind in KINDS}
    for directory, origin in sources:
        for info, entries in read_dir(directory, origin):
            infos.append(info.to_dict())
            for entry in entries:
                merged[info.kind][entry.id] = entry
    return PackSet(infos, merged["providers"].values(), merged["takeover"].values(), merged["signals"].values())
