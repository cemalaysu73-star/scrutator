import base64
import hashlib
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def default_key_dir() -> Path:
    return Path.home() / ".config" / "scrutator"


def private_key_path(key_dir: Path | None = None) -> Path:
    return (key_dir or default_key_dir()) / "signing.key"


def public_key_path(key_dir: Path | None = None) -> Path:
    return (key_dir or default_key_dir()) / "signing.pub"


def fingerprint(public_raw: bytes) -> str:
    """sha256 of the raw 32-byte public key, hex. This is what users pin."""
    return hashlib.sha256(public_raw).hexdigest()


def public_raw_from_private(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def generate_keypair(key_dir: Path) -> str:
    """Create signing.key (PEM, owner-only where the OS supports it) and signing.pub
    (base64 raw key). Refuses to overwrite. Returns the fingerprint."""
    key_dir.mkdir(parents=True, exist_ok=True)
    private_path = private_key_path(key_dir)
    if private_path.exists():
        raise FileExistsError(f"{private_path} already exists; refusing to overwrite a signing key")
    private = Ed25519PrivateKey.generate()
    pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    descriptor = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(pem)
    public_raw = public_raw_from_private(private)
    public_key_path(key_dir).write_text(base64.b64encode(public_raw).decode() + "\n", encoding="utf-8")
    return fingerprint(public_raw)


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{path} is not a usable private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 key")
    return key


def load_public_raw(path: Path) -> bytes:
    try:
        raw = base64.b64decode(path.read_text(encoding="utf-8").strip(), validate=True)
    except ValueError as exc:
        raise ValueError(f"{path} is not a base64 public key") from exc
    if len(raw) != 32:
        raise ValueError(f"{path} does not hold a 32-byte Ed25519 public key")
    return raw


def sign(private: Ed25519PrivateKey, data: bytes) -> bytes:
    return private.sign(data)


def verify_signature(public_raw: bytes, signature: bytes, data: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, data)
    except (InvalidSignature, ValueError):
        return False
    return True
