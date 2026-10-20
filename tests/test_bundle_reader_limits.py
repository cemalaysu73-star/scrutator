"""R4 A4: a bundle is untrusted input. Reading and verifying one must fail closed, with a clear message, in bounded
memory and time: zip bombs, archives with thousands of entries, lying headers, traversal names, duplicates,
symbolic links, encryption, truncation, oversized manifests, signature and key confusion."""

import base64
import json
import struct
import time
import tracemalloc
import zipfile

import pytest
from bundlefix import forge, make_bundle
from typer.testing import CliRunner

from scrutator import cli
from scrutator.bundle import reader
from scrutator.bundle.reader import BundleError, read_raw
from scrutator.bundle.verify import verify_bundle


def members(fx_path) -> dict[str, bytes]:
    with zipfile.ZipFile(fx_path) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def write_zip(path, entries, *, compression=zipfile.ZIP_DEFLATED):
    with zipfile.ZipFile(path, "w", compression) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return path


def fails_cleanly(path, expect: str):
    with pytest.raises(BundleError, match=expect):
        read_raw(path)
    result = verify_bundle(path)
    assert not result.ok and result.checks[0].name == "readable bundle"
    out = CliRunner().invoke(cli.app, ["verify", str(path)])
    assert out.exit_code == 1 and "Traceback" not in out.output and "FAIL  readable bundle" in out.output


def test_a_zip_bomb_is_refused_from_its_declared_size_without_inflating_it(tmp_path):
    """A member that inflates to more than the per-file limit (256 MiB) from a few hundred KiB on disk."""
    good = members(make_bundle(tmp_path).path)
    bomb = tmp_path / "bomb.scrutator"
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in good.items():
            if name != "evidence.jsonl":
                archive.writestr(name, data)
        with archive.open("evidence.jsonl", "w", force_zip64=False) as handle:
            chunk = b"\0" * (1024 * 1024)
            for _ in range(reader.MAX_FILE_BYTES // len(chunk) + 16):  # just over the limit in zeros, about 300 KiB on disk
                handle.write(chunk)
    assert bomb.stat().st_size < 2 * 1024 * 1024
    tracemalloc.start()
    started = time.perf_counter()
    with pytest.raises(BundleError, match="too large"):
        read_raw(bomb)
    elapsed = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert peak < 16 * 1024 * 1024 and elapsed < 2.0, (peak, elapsed)


def test_an_archive_with_thousands_of_entries_is_refused_before_they_are_listed(tmp_path, monkeypatch):
    many = write_zip(tmp_path / "many.scrutator", [(f"x{i}", b"") for i in range(3000)], compression=zipfile.ZIP_STORED)
    built = []
    real = zipfile.ZipFile
    monkeypatch.setattr(reader.zipfile, "ZipFile", lambda *a, **k: built.append(a) or real(*a, **k))
    with pytest.raises(BundleError, match="3000 entries"):
        read_raw(many)
    assert built == []  # refused from the end record, before the zip library parsed the directory


def test_a_header_that_lies_about_the_size_cannot_inflate_past_it(tmp_path):
    good = members(make_bundle(tmp_path).path)
    path = write_zip(tmp_path / "liar.scrutator", list(good.items()))
    raw = bytearray(path.read_bytes())
    # shrink the uncompressed size of evidence.jsonl in the central directory to 10 bytes
    at = 0
    for offset in [i for i in range(len(raw)) if raw[i : i + 4] == b"PK\x01\x02"]:
        name_len = struct.unpack("<H", raw[offset + 28 : offset + 30])[0]
        if bytes(raw[offset + 46 : offset + 46 + name_len]) == b"evidence.jsonl":
            raw[offset + 24 : offset + 28] = struct.pack("<I", 10)
            at = offset
    assert at
    path.write_bytes(bytes(raw))
    with pytest.raises(BundleError):
        read_raw(path)


@pytest.mark.parametrize("bad_name", ["../report.json", "/etc/passwd", "C:\\Windows\\x", "report.json/../../x", "./report.json", "REPORT.JSON", "report.json\x00.txt"])
def test_any_name_other_than_the_five_is_refused(tmp_path, bad_name):
    good = members(make_bundle(tmp_path).path)
    path = write_zip(tmp_path / "names.scrutator", [*good.items(), (bad_name, b"x")])
    fails_cleanly(path, "unexpected entry|duplicate")


def test_a_duplicate_member_is_refused(tmp_path):
    good = members(make_bundle(tmp_path).path)
    path = tmp_path / "dup.scrutator"
    with pytest.warns(UserWarning):
        write_zip(path, [*good.items(), ("report.json", b"{}")])
    fails_cleanly(path, "duplicate")


def test_a_symbolic_link_entry_is_only_bytes(tmp_path):
    fx = make_bundle(tmp_path)
    good = members(fx.path)
    path = tmp_path / "link.scrutator"
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in good.items():
            if name == "report.json":
                info = zipfile.ZipInfo(name)
                info.external_attr = (0o120777 << 16)  # a symlink to /etc/passwd, if anything extracted it
                archive.writestr(info, b"/etc/passwd")
            else:
                archive.writestr(name, data)
    assert read_raw(path).files["report.json"] == b"/etc/passwd"
    result = verify_bundle(path)
    assert not result.ok and any(c.name == "file hashes" and not c.ok for c in result.checks)


def test_truncated_empty_directory_and_non_zip_inputs_fail_cleanly(tmp_path):
    good = make_bundle(tmp_path).path.read_bytes()
    cases = {
        "truncated.scrutator": good[: len(good) // 2],
        "empty.scrutator": b"",
        "text.scrutator": b"just text\n" * 100,
        "tail-only.scrutator": good[-200:],
    }
    for name, data in cases.items():
        (tmp_path / name).write_bytes(data)
        fails_cleanly(tmp_path / name, "not a readable bundle")
    (tmp_path / "dir.scrutator").mkdir()
    fails_cleanly(tmp_path / "dir.scrutator", "not a file")
    fails_cleanly(tmp_path / "missing.scrutator", "not a file")


def test_an_oversized_manifest_or_signature_is_refused(tmp_path):
    good = members(make_bundle(tmp_path).path)
    big = {**good, "manifest.json": good["manifest.json"] + b" " * (2 * 1024 * 1024)}
    fails_cleanly(write_zip(tmp_path / "m.scrutator", list(big.items())), "manifest.json is too large")
    big = {**good, "manifest.sig": b"A" * 10000}
    fails_cleanly(write_zip(tmp_path / "s.scrutator", list(big.items())), "manifest.sig is too large")


def test_a_file_larger_than_the_limit_on_disk_is_refused_unread(tmp_path, monkeypatch):
    monkeypatch.setattr(reader, "MAX_BUNDLE_BYTES", 1000)
    fails_cleanly(make_bundle(tmp_path).path, "too large")


def test_an_encrypted_member_fails_cleanly(tmp_path):
    good = members(make_bundle(tmp_path).path)
    path = write_zip(tmp_path / "enc.scrutator", list(good.items()), compression=zipfile.ZIP_STORED)
    raw = bytearray(path.read_bytes())
    for offset in [i for i in range(len(raw)) if raw[i : i + 4] in (b"PK\x03\x04", b"PK\x01\x02")]:
        flag_at = offset + (6 if raw[offset + 2] == 3 else 8)
        raw[flag_at] |= 1  # the "encrypted" bit
    path.write_bytes(bytes(raw))
    fails_cleanly(path, "not a readable bundle|encrypted|password")


# ------------------------------------------------------------------------------------------ signatures and keys


def test_signature_and_key_confusion_fail(tmp_path):
    fx = make_bundle(tmp_path)
    good = members(fx.path)
    manifest = json.loads(good["manifest.json"])

    def with_manifest(name, change, sig=None):
        m = {**manifest, **change}
        data = {**good, "manifest.json": json.dumps(m, sort_keys=True, indent=2).encode()}
        if sig is not None:
            data["manifest.sig"] = sig
        return verify_bundle(write_zip(tmp_path / name, list(data.items())), pinned_fingerprint=fx.fingerprint)

    cases = [
        with_manifest("alg.scrutator", {"algorithm": "none"}, sig=b"\n"),  # an "unsigned" claim is not honoured
        with_manifest("key33.scrutator", {"public_key": base64.b64encode(b"\x01" * 33).decode()}),
        with_manifest("keyzero.scrutator", {"public_key": base64.b64encode(b"\x00" * 32).decode()}, sig=base64.b64encode(b"\x00" * 64)),
        with_manifest("sigjunk.scrutator", {}, sig=b"not base64 !!"),
        with_manifest("fp.scrutator", {"key_fingerprint": fx.fingerprint.upper()}),
    ]
    for result in cases:
        assert not result.ok
        assert any(c.name in ("signature valid", "signing key pinned", "key fingerprint") and not c.ok for c in result.checks)


@pytest.mark.parametrize("pin_form", ["{fp}", "sha256:{fp}", "{FP}", " {fp}\n"])
def test_a_pin_is_accepted_in_its_documented_forms_and_nothing_shorter(tmp_path, pin_form):
    fx = make_bundle(tmp_path)
    pin = pin_form.format(fp=fx.fingerprint, FP=fx.fingerprint.upper())
    assert verify_bundle(fx.path, pinned_fingerprint=pin).ok
    assert not verify_bundle(fx.path, pinned_fingerprint=fx.fingerprint[:16]).ok
    assert not verify_bundle(fx.path, pinned_fingerprint="").ok


def test_a_pinned_bundle_cannot_be_truncated_and_resigned(tmp_path):
    fx = make_bundle(tmp_path)
    attacker = make_bundle(tmp_path / "attacker").private

    def drop_last(data: bytes) -> bytes:
        return b"".join(data.splitlines(keepends=True)[:-1])

    forged = forge(fx.path, tmp_path / "t.scrutator", attacker, {"audit.jsonl": drop_last})
    assert not verify_bundle(forged, pinned_fingerprint=fx.fingerprint).ok


def test_verifying_a_real_size_bundle_is_fast(tmp_path):
    fx = make_bundle(tmp_path)
    started = time.perf_counter()
    for _ in range(5):
        assert verify_bundle(fx.path).ok
    assert (time.perf_counter() - started) / 5 < 2.0
