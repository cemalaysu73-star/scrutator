"""The Ed25519 key that signs proof bundles.

At rest the private key is either

- passphrase-protected (`scrutator keygen --passphrase`, recommended): the 32 raw key bytes sealed with
  ChaCha20-Poly1305 under a key derived from the passphrase with scrypt (N=2^16, r=8, p=1, a random 16-byte salt).
  The KDF parameters and the format version are authenticated as associated data, so a file whose parameters were
  weakened, or whose ciphertext was changed, does not open. The passphrase comes from the environment variable
  SCRUTATOR_KEY_PASSPHRASE or an interactive prompt, never from a command-line argument (which would land in shell
  history and the process list); or
- plain PKCS#8 PEM, as written by earlier versions. It keeps working, and every use warns.

File permissions: on POSIX the key file is created 0600 inside a 0700 directory, and a key readable by group or
others is reported. On Windows the mode bits do nothing beyond read-only; the file gets the ACL it inherits from its
directory (under the user profile that is normally the user, SYSTEM and Administrators). Scrutator does not set or
check Windows ACLs, which is why a passphrase matters more there.

No trusted timestamp: a signature proves who signed a bundle, not when. `created_at` in the manifest is the signer's
own clock. RFC 3161 timestamping is not implemented."""

import base64
import hashlib
import json
import os
import stat
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

PASSPHRASE_ENV = "SCRUTATOR_KEY_PASSPHRASE"
ENCRYPTED_HEADER = "-----BEGIN SCRUTATOR ENCRYPTED SIGNING KEY-----"
ENCRYPTED_FOOTER = "-----END SCRUTATOR ENCRYPTED SIGNING KEY-----"
KDF = {"name": "scrypt", "n": 2**16, "r": 8, "p": 1}
MIN_KDF = {"n": 2**14, "r": 8, "p": 1}  # a file asking for less work than this is refused (a downgraded file)
MIN_PASSPHRASE = 8


class KeyFileError(ValueError):
    """A key file that cannot be used: wrong passphrase, damaged file, weakened parameters."""


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
    return private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _derive(passphrase: str, salt: bytes, params: dict) -> bytes:
    return Scrypt(salt=salt, length=32, n=params["n"], r=params["r"], p=params["p"]).derive(passphrase.encode("utf-8"))


def _aad(envelope: dict) -> bytes:
    return json.dumps({k: envelope[k] for k in ("format", "kdf", "aead", "salt")}, sort_keys=True).encode()


def seal(private: Ed25519PrivateKey, passphrase: str, *, kdf: dict | None = None) -> bytes:
    """The encrypted key file's bytes."""
    if len(passphrase) < MIN_PASSPHRASE:
        raise KeyFileError(f"a passphrase must have at least {MIN_PASSPHRASE} characters")
    params = dict(kdf or KDF)
    salt, nonce = os.urandom(16), os.urandom(12)
    envelope = {"format": 1, "kdf": params, "aead": "chacha20poly1305", "salt": base64.b64encode(salt).decode()}
    raw = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    sealed = ChaCha20Poly1305(_derive(passphrase, salt, params)).encrypt(nonce, raw, _aad(envelope))
    envelope |= {"nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(sealed).decode()}
    body = base64.encodebytes(json.dumps(envelope, sort_keys=True).encode()).decode()
    return f"{ENCRYPTED_HEADER}\n{body}{ENCRYPTED_FOOTER}\n".encode()


def _open_sealed(data: bytes, passphrase: str) -> Ed25519PrivateKey:
    try:
        text = data.decode("ascii").strip()
        body = text.removeprefix(ENCRYPTED_HEADER).removesuffix(ENCRYPTED_FOOTER)
        envelope = json.loads(base64.b64decode(body))
        params = envelope["kdf"]
        if envelope.get("format") != 1 or envelope.get("aead") != "chacha20poly1305" or params.get("name") != "scrypt":
            raise KeyFileError("unsupported key file format")
        if any(int(params[k]) < MIN_KDF[k] for k in MIN_KDF) or int(params["n"]) > 2**20 or int(params["r"]) > 32 or int(params["p"]) > 16:
            raise KeyFileError("the key file's scrypt parameters are outside the accepted range")
        salt, nonce = base64.b64decode(envelope["salt"]), base64.b64decode(envelope["nonce"])
        sealed = base64.b64decode(envelope["ciphertext"])
    except KeyFileError:
        raise
    except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
        raise KeyFileError("the encrypted key file is damaged") from exc
    try:
        raw = ChaCha20Poly1305(_derive(passphrase, salt, params)).decrypt(nonce, sealed, _aad(envelope))
    except InvalidTag as exc:
        raise KeyFileError("wrong passphrase, or the key file was altered") from exc
    return Ed25519PrivateKey.from_private_bytes(raw)


def is_encrypted(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(len(ENCRYPTED_HEADER)).decode("ascii", "replace") == ENCRYPTED_HEADER
    except OSError:
        return False


def _write_private(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)


def generate_keypair(key_dir: Path, passphrase: str | None = None) -> str:
    """Create signing.key (encrypted when a passphrase is given; owner-only where the OS supports it) and
    signing.pub (base64 raw key). Refuses to overwrite. Returns the fingerprint."""
    key_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_path = private_key_path(key_dir)
    if private_path.exists():
        raise FileExistsError(f"{private_path} already exists; refusing to overwrite a signing key")
    private = Ed25519PrivateKey.generate()
    if passphrase is not None:
        data = seal(private, passphrase)
    else:
        data = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    _write_private(private_path, data)
    public_raw = public_raw_from_private(private)
    public_key_path(key_dir).write_text(base64.b64encode(public_raw).decode() + "\n", encoding="utf-8")
    return fingerprint(public_raw)


def protect_key(path: Path, passphrase: str) -> str:
    """Encrypt an existing plain key in place (the file is replaced atomically; the key, and so the fingerprint,
    stays the same). Returns the fingerprint."""
    private = load_private_key(path)
    temporary = path.with_name(path.name + ".new")
    if temporary.exists():
        temporary.unlink()
    _write_private(temporary, seal(private, passphrase))
    os.replace(temporary, path)
    return fingerprint(public_raw_from_private(private))


def permission_problem(path: Path) -> str:
    """On POSIX, why the key file's permissions are too open, or an empty string. Windows ACLs are not checked."""
    if os.name != "posix":
        return ""
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        return f"{path} is readable by other users (mode {stat.S_IMODE(mode):o}); run `chmod 600 {path}`"
    return ""


def load_private_key(path: Path, passphrase: str | None = None) -> Ed25519PrivateKey:
    data = path.read_bytes()
    if data.lstrip().startswith(ENCRYPTED_HEADER.encode()):
        if passphrase is None:
            raise KeyFileError(f"{path} is encrypted: set {PASSPHRASE_ENV} or run interactively to be asked for the passphrase")
        return _open_sealed(data, passphrase)
    try:
        key = serialization.load_pem_private_key(data, password=None)
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
