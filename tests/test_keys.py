import base64
import os

import pytest

from scrutator.bundle.keys import (
    fingerprint,
    generate_keypair,
    load_private_key,
    load_public_raw,
    private_key_path,
    public_key_path,
    public_raw_from_private,
    sign,
    verify_signature,
)


def test_generate_load_sign_and_verify(tmp_path):
    fp = generate_keypair(tmp_path)
    assert len(fp) == 64 and all(c in "0123456789abcdef" for c in fp)
    private = load_private_key(private_key_path(tmp_path))
    public = load_public_raw(public_key_path(tmp_path))
    assert public == public_raw_from_private(private) and fingerprint(public) == fp
    signature = sign(private, b"manifest")
    assert verify_signature(public, signature, b"manifest")
    assert not verify_signature(public, signature, b"manifesT")


def test_existing_keys_are_never_overwritten(tmp_path):
    generate_keypair(tmp_path)
    with pytest.raises(FileExistsError):
        generate_keypair(tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_private_key_is_owner_only(tmp_path):
    generate_keypair(tmp_path)
    assert private_key_path(tmp_path).stat().st_mode & 0o777 == 0o600


def test_bad_key_files_are_rejected(tmp_path):
    bad = tmp_path / "bad.pub"
    bad.write_text("not base64 at all!!")
    with pytest.raises(ValueError):
        load_public_raw(bad)
    short = tmp_path / "short.pub"
    short.write_text(base64.b64encode(b"too short").decode())
    with pytest.raises(ValueError):
        load_public_raw(short)
    notkey = tmp_path / "bad.key"
    notkey.write_text("-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n")
    with pytest.raises(ValueError):
        load_private_key(notkey)


def test_verify_signature_never_raises_on_garbage(tmp_path):
    generate_keypair(tmp_path)
    public = load_public_raw(public_key_path(tmp_path))
    assert verify_signature(public, b"short", b"data") is False
    assert verify_signature(b"wrong length", b"x" * 64, b"data") is False
