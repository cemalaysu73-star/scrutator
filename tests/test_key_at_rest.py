"""R4 A5: the signing key at rest. Passphrase protection (scrypt + ChaCha20-Poly1305), the passphrase only from the
environment or a prompt, plain keys still working with a warning, owner-only permissions on POSIX."""

import base64
import json
import os
import stat

import pytest
from typer.testing import CliRunner

from scrutator import cli
from scrutator.bundle.keys import (
    ENCRYPTED_HEADER,
    PASSPHRASE_ENV,
    KeyFileError,
    fingerprint,
    generate_keypair,
    is_encrypted,
    load_private_key,
    private_key_path,
    public_raw_from_private,
    seal,
)
from scrutator.bundle.verify import verify_bundle

PASS = "correct horse battery staple"
runner = CliRunner()


@pytest.fixture(autouse=True)
def no_passphrase_in_env(monkeypatch):
    monkeypatch.delenv(PASSPHRASE_ENV, raising=False)


def test_an_encrypted_key_round_trips_and_holds_no_plain_key_material(tmp_path):
    fp = generate_keypair(tmp_path, PASS)
    path = private_key_path(tmp_path)
    data = path.read_bytes()
    assert data.startswith(ENCRYPTED_HEADER.encode()) and b"PRIVATE KEY" not in data and is_encrypted(path)
    key = load_private_key(path, PASS)
    assert fingerprint(public_raw_from_private(key)) == fp
    from cryptography.hazmat.primitives import serialization

    secret = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    assert secret not in data and base64.b64encode(secret) not in data


def test_a_wrong_passphrase_a_missing_one_and_a_tampered_file_all_fail(tmp_path):
    generate_keypair(tmp_path, PASS)
    path = private_key_path(tmp_path)
    with pytest.raises(KeyFileError, match="wrong passphrase"):
        load_private_key(path, PASS + "x")
    with pytest.raises(KeyFileError, match=PASSPHRASE_ENV):
        load_private_key(path)
    text = path.read_text()
    body = text.split("\n", 1)[1].rsplit("-----END", 1)[0]
    envelope = json.loads(base64.b64decode(body))
    for change in ({"kdf": {**envelope["kdf"], "n": 2**10}}, {"salt": base64.b64encode(b"\0" * 16).decode()}):
        forged = {**envelope, **change}
        path.write_text(text.split("\n", 1)[0] + "\n" + base64.encodebytes(json.dumps(forged).encode()).decode() + "-----END SCRUTATOR ENCRYPTED SIGNING KEY-----\n")
        with pytest.raises(KeyFileError):
            load_private_key(path, PASS)  # weakened parameters are refused; a changed salt fails authentication
    path.write_text(text.replace(text.split("\n")[1][:10], "AAAAAAAAAA", 1))
    with pytest.raises(KeyFileError):
        load_private_key(path, PASS)


def test_a_short_passphrase_is_refused():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    with pytest.raises(KeyFileError, match="at least"):
        seal(Ed25519PrivateKey.generate(), "short")


def test_keygen_takes_the_passphrase_from_the_environment_never_from_an_argument(tmp_path, monkeypatch):
    help_text = runner.invoke(cli.app, ["keygen", "--help"]).output
    assert "--passphrase" in help_text and PASSPHRASE_ENV in help_text
    with_value = runner.invoke(cli.app, ["keygen", "--key-dir", str(tmp_path / "a"), "--passphrase", PASS])
    assert with_value.exit_code != 0  # a value after the flag is not accepted as the passphrase
    no_terminal = runner.invoke(cli.app, ["keygen", "--key-dir", str(tmp_path / "b"), "--passphrase"])
    assert no_terminal.exit_code == 2 and PASSPHRASE_ENV in no_terminal.output and not (tmp_path / "b" / "signing.key").exists()
    monkeypatch.setenv(PASSPHRASE_ENV, PASS)
    made = runner.invoke(cli.app, ["keygen", "--key-dir", str(tmp_path / "c"), "--passphrase"])
    assert made.exit_code == 0, made.output
    assert is_encrypted(tmp_path / "c" / "signing.key") and PASS not in made.output


def test_signing_with_an_encrypted_key_needs_its_passphrase_and_the_bundle_verifies(tmp_path, monkeypatch):
    from bundlefix import make_store

    from scrutator.bundle.writer import create_bundle

    monkeypatch.setenv(PASSPHRASE_ENV, PASS)
    assert runner.invoke(cli.app, ["keygen", "--key-dir", str(tmp_path / "k"), "--passphrase"]).exit_code == 0
    store, scan_id, _ = make_store()
    key = cli._signing_key(tmp_path / "k")
    create_bundle(store, scan_id, key, tmp_path / "p.scrutator")
    assert verify_bundle(tmp_path / "p.scrutator").ok
    assert PASS.encode() not in (tmp_path / "p.scrutator").read_bytes()
    monkeypatch.delenv(PASSPHRASE_ENV)
    with pytest.raises(Exception) as refused:  # typer.Exit(2) with the reason on stderr
        cli._signing_key(tmp_path / "k")
    assert getattr(refused.value, "exit_code", None) == 2


def test_a_plain_key_still_signs_with_a_warning_and_can_be_protected_in_place(tmp_path, monkeypatch, capsys):
    fp = generate_keypair(tmp_path)
    key = cli._signing_key(tmp_path)
    assert "not encrypted" in capsys.readouterr().err and fingerprint(public_raw_from_private(key)) == fp
    monkeypatch.setenv(PASSPHRASE_ENV, PASS)
    result = runner.invoke(cli.app, ["protect-key", "--key-dir", str(tmp_path)])
    assert result.exit_code == 0 and fp in result.output, result.output
    assert is_encrypted(private_key_path(tmp_path))
    assert fingerprint(public_raw_from_private(load_private_key(private_key_path(tmp_path), PASS))) == fp
    again = runner.invoke(cli.app, ["protect-key", "--key-dir", str(tmp_path)])
    assert again.exit_code == 2 and "already encrypted" in again.output
    assert not (tmp_path / "signing.key.new").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions; Windows ACLs are not set or checked (documented)")
def test_on_posix_the_key_is_owner_only_and_a_loose_one_is_reported(tmp_path, capsys):
    generate_keypair(tmp_path / "k", PASS)
    path = private_key_path(tmp_path / "k")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and stat.S_IMODE((tmp_path / "k").stat().st_mode) & 0o077 == 0
    os.chmod(path, 0o644)
    os.environ[PASSPHRASE_ENV] = PASS
    try:
        cli._signing_key(tmp_path / "k")
    finally:
        del os.environ[PASSPHRASE_ENV]
    assert "readable by other users" in capsys.readouterr().err
