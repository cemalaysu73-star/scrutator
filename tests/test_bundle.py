import base64
import hashlib
import json
import zipfile

import pytest
from bundlefix import make_bundle

from scrutator.bundle import reader
from scrutator.bundle.keys import verify_signature
from scrutator.bundle.reader import ALLOWED, BundleError, read_raw


def test_bundle_has_exactly_the_expected_files_and_a_valid_signature(tmp_path):
    fx = make_bundle(tmp_path)
    with zipfile.ZipFile(fx.path) as archive:
        assert sorted(archive.namelist()) == sorted(ALLOWED)
    files = read_raw(fx.path).files
    manifest = json.loads(files["manifest.json"])
    assert manifest["format"] == 1
    assert manifest["scan"]["seed"] == "example.com"
    assert manifest["key_fingerprint"] == fx.fingerprint
    for name in ("report.json", "evidence.jsonl", "audit.jsonl"):
        assert manifest["files"][name] == {"sha256": hashlib.sha256(files[name]).hexdigest(), "bytes": len(files[name])}
    public = base64.b64decode(manifest["public_key"])
    signature = base64.b64decode(files["manifest.sig"].strip())
    assert verify_signature(public, signature, files["manifest.json"])


def test_bundle_content_matches_the_scan(tmp_path):
    fx = make_bundle(tmp_path)
    files = read_raw(fx.path).files
    report = json.loads(files["report.json"])
    assert report["scan"]["seed"] == "example.com"
    assert report["scope"] == {"domains": ["example.com"], "cidrs": [], "asns": []}
    assert [s["text"] for s in report["summary_statements"]] == ["www exists"]
    evidence = [json.loads(line) for line in files["evidence.jsonl"].decode().splitlines()]
    assert {e["id"] for e in evidence} == set(fx.evidence.values())
    assert {"id", "source", "request", "payload", "collected_at"} == set(evidence[0])
    audit = [json.loads(line) for line in files["audit.jsonl"].decode().splitlines()]
    assert [a["seq"] for a in audit] == [1, 2, 3]
    assert set(audit[0]) == {"seq", "prev_hash", "hash", "record"}


def test_writing_is_atomic_and_overwrites(tmp_path):
    fx = make_bundle(tmp_path)
    from scrutator.bundle.writer import create_bundle

    create_bundle(fx.store, fx.scan_id, fx.private, fx.path)
    assert not list(tmp_path.glob("*.tmp"))
    assert zipfile.is_zipfile(fx.path)


def test_reader_rejects_unreadable_and_hostile_archives(tmp_path):
    notzip = tmp_path / "x.scrutator"
    notzip.write_bytes(b"this is not a zip")
    with pytest.raises(BundleError):
        read_raw(notzip)

    fx = make_bundle(tmp_path)
    files = read_raw(fx.path).files

    def build(name, extra=None, drop=None):
        path = tmp_path / name
        with zipfile.ZipFile(path, "w") as archive:
            for entry, data in files.items():
                if entry != drop:
                    archive.writestr(entry, data)
            for entry, data in (extra or {}).items():
                archive.writestr(entry, data)
        return path

    with pytest.raises(BundleError, match="unexpected"):
        read_raw(build("a.scrutator", extra={"../evil.txt": b"x"}))
    with pytest.raises(BundleError, match="unexpected"):
        read_raw(build("b.scrutator", extra={"extra.json": b"{}"}))
    with pytest.raises(BundleError, match="missing"):
        read_raw(build("c.scrutator", drop="audit.jsonl"))


def test_reader_rejects_duplicate_entries_and_oversize_files(tmp_path, monkeypatch):
    fx = make_bundle(tmp_path)
    dup = tmp_path / "dup.scrutator"
    with zipfile.ZipFile(dup, "w") as archive:
        for entry, data in read_raw(fx.path).files.items():
            archive.writestr(entry, data)
        with pytest.warns(UserWarning):
            archive.writestr("report.json", b"{}")
    with pytest.raises(BundleError, match="duplicate"):
        read_raw(dup)
    monkeypatch.setattr(reader, "MAX_FILE_BYTES", 10)
    with pytest.raises(BundleError, match="too large"):
        read_raw(fx.path)
