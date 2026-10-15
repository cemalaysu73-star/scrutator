import base64
import hashlib
import json
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scrutator import __version__
from scrutator.bundle.keys import fingerprint, public_raw_from_private, sign
from scrutator.report import build_report, render_json
from scrutator.store import Store

FORMAT_VERSION = 1
DATA_FILES = ("report.json", "evidence.jsonl", "audit.jsonl")


def _jsonl(items: list[dict]) -> bytes:
    body = "\n".join(json.dumps(item, sort_keys=True) for item in items)
    return (body + "\n").encode("utf-8") if items else b""


def create_bundle(
    store: Store,
    scan_id: int,
    private_key: Ed25519PrivateKey,
    path: str | Path,
    *,
    now: str | None = None,
) -> dict[str, Any]:
    """Write a signed proof bundle for a scan and return its manifest."""
    seed, started_at = store.get_scan(scan_id)
    report = build_report(store, scan_id)
    files = {
        "report.json": render_json(report).encode("utf-8"),
        "evidence.jsonl": _jsonl(
            [
                {
                    "id": ev.id,
                    "source": ev.source,
                    "request": ev.request,
                    "payload": ev.payload,
                    "collected_at": ev.collected_at,
                }
                for ev in store.evidence_for_scan(scan_id)
            ]
        ),
        "audit.jsonl": _jsonl(store.audit_rows(scan_id)),
    }
    public_raw = public_raw_from_private(private_key)
    manifest = {
        "format": FORMAT_VERSION,
        "tool": {"name": "scrutator", "version": __version__},
        "created_at": now or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scan": {"id": scan_id, "seed": seed, "started_at": started_at},
        "files": {
            name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
            for name, data in files.items()
        },
        "public_key": base64.b64encode(public_raw).decode(),
        "key_fingerprint": fingerprint(public_raw),
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8")
    signature = base64.b64encode(sign(private_key, manifest_bytes)) + b"\n"

    target = Path(path)
    temporary = target.with_name(target.name + ".tmp")
    with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in {**files, "manifest.json": manifest_bytes, "manifest.sig": signature}.items():
            archive.writestr(name, data)
    os.replace(temporary, target)
    return manifest
