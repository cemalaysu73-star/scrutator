import json
import zipfile

import pytest
from bundlefix import DATA_FILES, forge, make_bundle, rewrite
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scrutator.bundle.verify import verify_bundle


def check(report, name):
    return next(c for c in report.checks if c.name == name)


def test_a_genuine_bundle_passes_and_warns_that_the_key_is_not_pinned(tmp_path):
    fx = make_bundle(tmp_path)
    report = verify_bundle(fx.path)
    assert report.ok, [c for c in report.checks if not c.ok]
    assert report.key_fingerprint == fx.fingerprint
    assert len(report.warnings) == 1 and "not pinned" in report.warnings[0]
    assert {c.name for c in report.checks} >= {
        "readable bundle", "manifest parses", "file hashes", "signature valid",
        "audit chain", "evidence hashes", "report references", "findings derivable", "scan identity",
    }


def test_pinning_the_right_key_removes_the_warning_and_the_wrong_key_fails(tmp_path):
    fx = make_bundle(tmp_path)
    good = verify_bundle(fx.path, pinned_fingerprint=fx.fingerprint)
    assert good.ok and good.warnings == [] and check(good, "signing key pinned").ok
    assert verify_bundle(fx.path, pinned_fingerprint="sha256:" + fx.fingerprint.upper()).ok
    bad = verify_bundle(fx.path, pinned_fingerprint="0" * 64)
    assert not bad.ok and not check(bad, "signing key pinned").ok


@pytest.mark.parametrize("name", DATA_FILES)
def test_flipping_a_byte_in_any_data_file_breaks_the_file_hashes(tmp_path, name):
    fx = make_bundle(tmp_path)

    def flip(data: bytes) -> bytes:
        return data[:5] + bytes([data[5] ^ 1]) + data[6:]

    tampered = rewrite(fx.path, tmp_path / "t.scrutator", name, flip)
    report = verify_bundle(tampered)
    assert not report.ok and not check(report, "file hashes").ok


def test_editing_the_manifest_breaks_the_signature(tmp_path):
    fx = make_bundle(tmp_path)

    def edit(data: bytes) -> bytes:
        manifest = json.loads(data)
        manifest["scan"]["seed"] = "victim.org"
        return json.dumps(manifest, sort_keys=True, indent=2).encode()

    report = verify_bundle(rewrite(fx.path, tmp_path / "t.scrutator", "manifest.json", edit))
    assert not report.ok and not check(report, "signature valid").ok


def test_an_attacker_who_resigns_with_their_own_key_is_caught_by_pinning(tmp_path):
    fx = make_bundle(tmp_path)
    attacker = Ed25519PrivateKey.generate()
    forged = forge(fx.path, tmp_path / "f.scrutator", attacker, {})
    unpinned = verify_bundle(forged)
    assert unpinned.ok and "not pinned" in unpinned.warnings[0]  # why pinning matters
    pinned = verify_bundle(forged, pinned_fingerprint=fx.fingerprint)
    assert not pinned.ok and not check(pinned, "signing key pinned").ok


def test_a_tampered_audit_log_is_caught_even_when_resigned_with_the_real_key(tmp_path):
    fx = make_bundle(tmp_path)

    def tamper(data: bytes) -> bytes:
        lines = data.decode().splitlines()
        first = json.loads(lines[0])
        first["record"] = first["record"].replace("crtsh", "dns")
        lines[0] = json.dumps(first, sort_keys=True)
        return ("\n".join(lines) + "\n").encode()

    report = verify_bundle(forge(fx.path, tmp_path / "f.scrutator", fx.private, {"audit.jsonl": tamper}))
    assert check(report, "signature valid").ok and not check(report, "audit chain").ok and not report.ok


def test_altered_evidence_content_is_caught_by_its_hash(tmp_path):
    fx = make_bundle(tmp_path)

    def tamper(data: bytes) -> bytes:
        lines = data.decode().splitlines()
        first = json.loads(lines[0])
        first["payload"] = first["payload"] + " edited"
        lines[0] = json.dumps(first, sort_keys=True)
        return ("\n".join(lines) + "\n").encode()

    report = verify_bundle(forge(fx.path, tmp_path / "f.scrutator", fx.private, {"evidence.jsonl": tamper}))
    assert check(report, "signature valid").ok and not check(report, "evidence hashes").ok


def test_a_dropped_evidence_record_is_caught_by_the_references(tmp_path):
    fx = make_bundle(tmp_path)

    def drop(data: bytes) -> bytes:
        return ("\n".join(data.decode().splitlines()[1:]) + "\n").encode()

    report = verify_bundle(forge(fx.path, tmp_path / "f.scrutator", fx.private, {"evidence.jsonl": drop}))
    assert check(report, "evidence hashes").ok and not check(report, "report references").ok


def test_inflated_confidence_is_caught_because_findings_must_follow_from_evidence(tmp_path):
    fx = make_bundle(tmp_path)

    def inflate(data: bytes) -> bytes:
        report = json.loads(data)
        report["findings"][0]["confidence"] = "high"
        return json.dumps(report, indent=2, sort_keys=True).encode()

    report = verify_bundle(forge(fx.path, tmp_path / "f.scrutator", fx.private, {"report.json": inflate}))
    assert check(report, "signature valid").ok and not check(report, "findings derivable").ok


def test_a_report_for_a_different_scan_than_the_manifest_is_caught(tmp_path):
    fx = make_bundle(tmp_path)

    def relabel(data: bytes) -> bytes:
        report = json.loads(data)
        report["scan"]["seed"] = "other.net"
        return json.dumps(report, indent=2, sort_keys=True).encode()

    report = verify_bundle(forge(fx.path, tmp_path / "f.scrutator", fx.private, {"report.json": relabel}))
    assert not check(report, "scan identity").ok


def test_garbage_input_fails_cleanly(tmp_path):
    notzip = tmp_path / "x.scrutator"
    notzip.write_bytes(b"nope")
    report = verify_bundle(notzip)
    assert not report.ok and report.checks[0].name == "readable bundle"
    hostile = tmp_path / "h.scrutator"
    with zipfile.ZipFile(hostile, "w") as archive:
        archive.writestr("../../etc/passwd", b"x")
    assert not verify_bundle(hostile).ok
