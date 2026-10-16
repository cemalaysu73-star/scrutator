"""A small scan that carries real risks, packed into a signed bundle, plus a forger that can
change the report and the manifest and sign again with the genuine key."""

import base64
import hashlib
import json
import zipfile
from pathlib import Path

from bundlefix import DATA_FILES, Fixture
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


def dom(value):
    return Entity(type=EntityType.DOMAIN, value=value)


def make_risky_store(packs=None, path=":memory:"):
    """example.com with a weak SPF record, a dangling CNAME to an Azure host, and a certificate
    name that DNS does not know."""
    store = Store(path)
    sid = store.create_scan("example.com")
    root, shop, old = dom("example.com"), dom("shop.example.com"), dom("old.example.com")
    for entity in (root, shop, old):
        store.upsert_entity(sid, entity, ScopeState.IN)
    spf_target, azure = dom("_spf.google.com"), dom("shop-demo.azurewebsites.net")
    store.upsert_entity(sid, spf_target, ScopeState.OUT)
    store.upsert_entity(sid, azure, ScopeState.OUT)
    spf = Evidence.create("dns", "DNS TXT example.com", '"v=spf1 include:_spf.google.com +all"')
    cname = Evidence.create("dns", "DNS CNAME shop.example.com", "shop-demo.azurewebsites.net.")
    shop_nx = Evidence.create("dns", "DNS A shop.example.com", "NXDOMAIN")
    crt = Evidence.create(
        "crtsh",
        "GET https://crt.sh/?q=%25.example.com&output=json",
        json.dumps([{"id": 1, "issuer_name": "C=US, O=Let's Encrypt, CN=R3", "name_value": "old.example.com", "not_after": "2026-12-01T00:00:00", "not_before": "2026-09-01T00:00:00"}], sort_keys=True),
    )
    old_nx = Evidence.create("dns", "DNS A old.example.com", "NXDOMAIN")
    for ev in (spf, cname, shop_nx, crt, old_nx):
        store.add_evidence(ev)
    store.add_edge(sid, root.id, "spf_include", spf_target.id, [spf.id])
    store.add_edge(sid, shop.id, "cname_to", azure.id, [cname.id])
    store.add_edge(sid, root.id, "has_subdomain", old.id, [crt.id])
    store.add_scan_evidence(sid, shop_nx.id)
    store.add_scan_evidence(sid, old_nx.id)
    for ev, entity in ((spf, root), (cname, shop), (crt, root)):
        store.append_audit(sid, {"event": "ok", "module": ev.source, "entity": entity.id, "evidence_ids": [ev.id]})
    store.append_audit(sid, {"event": "ok", "module": "dns", "entity": shop.id, "evidence_ids": [shop_nx.id]})
    store.append_audit(sid, {"event": "ok", "module": "dns", "entity": old.id, "evidence_ids": [old_nx.id]})
    store.set_meta(sid, "scope", json.dumps({"domains": ["example.com"], "cidrs": [], "asns": []}))
    if packs is not None:
        store.set_meta(sid, "packs", json.dumps(packs.to_dict(), sort_keys=True))
    return store, sid


def make_risky_bundle(tmp_path: Path, packs=None) -> Fixture:
    store, sid = make_risky_store(packs)
    key_dir = tmp_path / "keys"
    fp = generate_keypair(key_dir)
    private = load_private_key(private_key_path(key_dir))
    path = tmp_path / "proof.scrutator"
    create_bundle(store, sid, private, path)
    return Fixture(path, private, fp, store, sid, {})


def forge_report(src: Path, dst: Path, private, change_report=None, change_manifest=None) -> Path:
    """Apply `change_report(report_dict)` and `change_manifest(manifest_dict)` in place, then
    rebuild the file hashes and sign with `private`: a compromised writer with the real key."""
    raw = read_raw(src).files
    files = {name: raw[name] for name in DATA_FILES}
    if change_report is not None:
        report = json.loads(files["report.json"])
        change_report(report)
        files["report.json"] = json.dumps(report, indent=2, sort_keys=True).encode()
    manifest = json.loads(raw["manifest.json"])
    if change_manifest is not None:
        change_manifest(manifest)
    manifest["files"] = {name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)} for name, data in files.items()}
    public = public_raw_from_private(private)
    manifest["public_key"] = base64.b64encode(public).decode()
    manifest["key_fingerprint"] = fingerprint(public)
    manifest_bytes = json.dumps(manifest, sort_keys=True, indent=2).encode()
    signature = base64.b64encode(sign(private, manifest_bytes)) + b"\n"
    with zipfile.ZipFile(dst, "w") as archive:
        for entry, data in {**files, "manifest.json": manifest_bytes, "manifest.sig": signature}.items():
            archive.writestr(entry, data)
    return dst
