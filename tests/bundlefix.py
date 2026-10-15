"""A small but complete scan, used to build bundles in several test files."""

import base64
import hashlib
import json
import zipfile
from dataclasses import dataclass
from pathlib import Path

from scrutator.bundle.keys import (
    fingerprint,
    generate_keypair,
    load_private_key,
    private_key_path,
    public_raw_from_private,
    sign,
)
from scrutator.bundle.reader import read_raw
from scrutator.bundle.writer import create_bundle
from scrutator.model import Entity, EntityType, Evidence, ScopeState
from scrutator.store import Store


def make_store() -> tuple[Store, int, dict[str, str]]:
    store = Store(":memory:")
    sid = store.create_scan("example.com")
    root = Entity(type=EntityType.DOMAIN, value="example.com")
    www = Entity(type=EntityType.DOMAIN, value="www.example.com")
    ip = Entity(type=EntityType.IP, value="192.0.2.10")
    for entity in (root, www, ip):
        store.upsert_entity(sid, entity, ScopeState.IN)
    ev_a = Evidence.create("crtsh", "GET https://crt.sh/?q=%25.example.com&output=json", '[{"name_value": "www.example.com"}]')
    ev_b = Evidence.create("wayback", "GET https://web.archive.org/cdx/search/cdx?url=*.example.com", '["http://www.example.com/"]')
    ev_c = Evidence.create("dns", "DNS A www.example.com", "192.0.2.10")
    for ev in (ev_a, ev_b, ev_c):
        store.add_evidence(ev)
    store.add_edge(sid, root.id, "has_subdomain", www.id, [ev_a.id, ev_b.id])
    store.add_edge(sid, www.id, "resolves_to", ip.id, [ev_c.id])
    store.append_audit(sid, {"event": "ok", "module": "crtsh", "entity": root.id, "evidence_ids": [ev_a.id]})
    store.append_audit(sid, {"event": "ok", "module": "wayback", "entity": root.id, "evidence_ids": [ev_b.id]})
    store.append_audit(sid, {"event": "ok", "module": "dns", "entity": www.id, "evidence_ids": [ev_c.id]})
    store.add_statement(sid, text="www exists", evidence_ids=[ev_a.id, ev_b.id], status="verified", confidence="medium")
    store.set_meta(sid, "scope", json.dumps({"domains": ["example.com"], "cidrs": [], "asns": []}))
    return store, sid, {"crtsh": ev_a.id, "wayback": ev_b.id, "dns": ev_c.id}


@dataclass
class Fixture:
    path: Path
    private: object
    fingerprint: str
    store: Store
    scan_id: int
    evidence: dict[str, str]


def make_bundle(tmp_path: Path) -> Fixture:
    store, sid, evidence = make_store()
    key_dir = tmp_path / "keys"
    fp = generate_keypair(key_dir)
    private = load_private_key(private_key_path(key_dir))
    path = tmp_path / "proof.scrutator"
    create_bundle(store, sid, private, path)
    return Fixture(path, private, fp, store, sid, evidence)


DATA_FILES = ("report.json", "evidence.jsonl", "audit.jsonl")


def rewrite(src: Path, dst: Path, name: str, change) -> Path:
    """Copy a bundle, changing one file's bytes and nothing else (manifest untouched)."""
    files = read_raw(src).files
    files[name] = change(files[name]) if callable(change) else change
    with zipfile.ZipFile(dst, "w") as archive:
        for entry, data in files.items():
            archive.writestr(entry, data)
    return dst


def forge(src: Path, dst: Path, private, changes: dict) -> Path:
    """Change data files, then rebuild the manifest hashes and sign it with `private`,
    as a compromised writer or a determined attacker would."""
    raw = read_raw(src).files
    files = {n: raw[n] for n in DATA_FILES}
    for name, change in changes.items():
        files[name] = change(files[name]) if callable(change) else change
    manifest = json.loads(raw["manifest.json"])
    manifest["files"] = {
        n: {"sha256": hashlib.sha256(d).hexdigest(), "bytes": len(d)} for n, d in files.items()
    }
    public = public_raw_from_private(private)
    manifest["public_key"] = base64.b64encode(public).decode()
    manifest["key_fingerprint"] = fingerprint(public)
    manifest_bytes = json.dumps(manifest, sort_keys=True, indent=2).encode()
    signature = base64.b64encode(sign(private, manifest_bytes)) + b"\n"
    with zipfile.ZipFile(dst, "w") as archive:
        for entry, data in {**files, "manifest.json": manifest_bytes, "manifest.sig": signature}.items():
            archive.writestr(entry, data)
    return dst
