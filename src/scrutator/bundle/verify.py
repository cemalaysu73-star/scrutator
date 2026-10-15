import base64
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from scrutator.bundle.keys import fingerprint, verify_signature
from scrutator.bundle.reader import BundleError, read_raw
from scrutator.findings import findings_from_report
from scrutator.store import GENESIS_HASH, chain_hash

_DATA_FILES = {"report.json", "evidence.jsonl", "audit.jsonl"}


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class VerifyReport:
    checks: list[Check] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    key_fingerprint: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(c.ok for c in self.checks)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _jsonl(data: bytes) -> list[dict]:
    rows = []
    for line in data.decode("utf-8").splitlines():
        if line.strip():
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError("a line is not a JSON object")
            rows.append(value)
    return rows


def verify_bundle(path: str | Path, *, pinned_fingerprint: str | None = None) -> VerifyReport:
    """Check every layer of a bundle independently. A failure in one layer does not hide
    the others, so the output says exactly what was altered."""
    result = VerifyReport()

    def add(name: str, ok: bool, detail: str = "") -> None:
        result.checks.append(Check(name, ok, detail))

    try:
        raw = read_raw(path)
    except BundleError as exc:
        add("readable bundle", False, str(exc))
        return result
    add("readable bundle", True)

    try:
        manifest = json.loads(raw.files["manifest.json"])
        if not isinstance(manifest, dict):
            raise ValueError("manifest is not an object")
        add("manifest parses", True)
    except ValueError as exc:
        add("manifest parses", False, str(exc))
        return result

    problems = []
    declared = manifest.get("files")
    if not isinstance(declared, dict) or set(declared) != _DATA_FILES:
        problems.append("the manifest does not list exactly the three data files")
    else:
        for name, info in declared.items():
            data = raw.files[name]
            if not isinstance(info, dict) or info.get("sha256") != _sha256(data) or info.get("bytes") != len(data):
                problems.append(f"{name} does not match the manifest")
    add("file hashes", not problems, "; ".join(problems))

    public = b""
    try:
        public = base64.b64decode(manifest["public_key"], validate=True)
        signature = base64.b64decode(raw.files["manifest.sig"].strip(), validate=True)
        valid = verify_signature(public, signature, raw.files["manifest.json"])
    except (KeyError, ValueError, TypeError):
        valid = False
    add("signature valid", valid, "" if valid else "manifest.sig does not match manifest.json and the embedded key")
    result.key_fingerprint = fingerprint(public) if len(public) == 32 else ""
    if manifest.get("key_fingerprint") != result.key_fingerprint:
        add("key fingerprint", False, "the manifest's key_fingerprint does not match its public key")

    if pinned_fingerprint is not None:
        wanted = pinned_fingerprint.strip().lower().removeprefix("sha256:")
        pinned_ok = valid and result.key_fingerprint == wanted
        add("signing key pinned", pinned_ok, "" if pinned_ok else f"signed by {result.key_fingerprint or 'an unreadable key'}, not {wanted}")
    else:
        result.warnings.append(
            "signing key is not pinned: a valid signature only proves the bundle matches the key inside "
            "it, and anyone can sign a forged bundle with their own key. Pin the signer with --pin."
        )

    # audit chain
    try:
        previous, expected, bad = GENESIS_HASH, 1, ""
        for row in _jsonl(raw.files["audit.jsonl"]):
            if row["seq"] != expected or row["prev_hash"] != previous:
                bad = f"record {expected} does not follow the previous one"
                break
            if chain_hash(previous, row["record"]) != row["hash"]:
                bad = f"record {expected} was altered"
                break
            previous, expected = row["hash"], expected + 1
        add("audit chain", not bad, bad)
    except (ValueError, KeyError, TypeError) as exc:
        add("audit chain", False, f"malformed audit log: {exc}")

    # evidence content addressing
    evidence_ids: set[str] = set()
    try:
        bad_ids = []
        for row in _jsonl(raw.files["evidence.jsonl"]):
            expected_id = _sha256(f"{row['source']}\n{row['request']}\n{row['payload']}".encode())
            if row["id"] != expected_id:
                bad_ids.append(str(row["id"])[:12])
            evidence_ids.add(row["id"])
        add("evidence hashes", not bad_ids, f"altered records: {', '.join(bad_ids[:5])}" if bad_ids else "")
    except (ValueError, KeyError, TypeError) as exc:
        add("evidence hashes", False, f"malformed evidence: {exc}")

    # the report and what it cites
    try:
        report = json.loads(raw.files["report.json"])
        cited: set[str] = set()
        for finding in report["findings"]:
            cited.update(finding["evidence_ids"])
        for edge in report["edges"]:
            cited.update(edge["evidence_ids"])
        for statement in report["summary_statements"]:
            cited.update(statement["evidence_ids"])
        missing = sorted(cited - evidence_ids)
        also_missing = sorted(cited - set(report["evidence"]))
        add(
            "report references",
            not missing and not also_missing,
            f"{len(set(missing + also_missing))} cited evidence record(s) are not in the bundle" if missing or also_missing else "",
        )
        derivable = findings_from_report(report) == report["findings"]
        add("findings derivable", derivable, "" if derivable else "the findings are not what the cited evidence implies")
        same_scan = report["scan"]["seed"] == manifest["scan"]["seed"]
        add("scan identity", same_scan, "" if same_scan else "the report is for a different scan than the manifest")
    except (ValueError, KeyError, TypeError) as exc:
        add("report references", False, f"malformed report: {exc}")
    return result
