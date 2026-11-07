"""TLS posture of an open TLS port: handshake only.

Two kinds of probe, each a TCP connection followed by a TLS handshake that is then closed. Nothing is sent after it.

- `TLS HANDSHAKE <address>:<port> sni=<name>`: what the server presents. Protocol and cipher negotiated, certificate
  subject, alternative names, issuer, validity, whether it covers the in-scope name asked for. The certificate chain is NOT
  validated (a self-signed or private-CA certificate is read like any other); expiry and name mismatch are what the
  rules look at.
- `TLS LEGACY <address>:<port> TLSv1|TLSv1.1`: whether the server still completes a handshake restricted to that old
  protocol. The result is `accepted`, `refused`, `unsupported` (this machine's TLS library cannot offer that protocol,
  established by a handshake against an in-process server, so nothing is concluded about the target) or `error`.
"""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import json
import ssl
import warnings

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from scrutator.active.guard import Budget, Limits
from scrutator.active.net import BudgetSpent, ProbeRefused, clean_text, close, connect
from scrutator.model import Evidence

MAX_SAN = 50
with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    LEGACY = {"TLSv1": ssl.TLSVersion.TLSv1, "TLSv1.1": ssl.TLSVersion.TLSv1_1}


def client_context(*, low: ssl.TLSVersion | None = None, high: ssl.TLSVersion | None = None) -> ssl.SSLContext:
    """A client context that accepts any certificate (the posture is read, not trusted). With `low` and `high`, restricted to
    that protocol range and with the OpenSSL security level lowered so an old protocol can be offered at all."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if low is not None:
        context.set_ciphers("ALL:@SECLEVEL=0")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)  # TLS 1.0 and 1.1 are deprecated: offering them is the point
            context.minimum_version = low
            context.maximum_version = high or low
    return context


def hostname_matches(name: str, patterns: list[str]) -> bool:
    """Does one of the certificate's DNS names cover `name`? A wildcard covers exactly one label, at the left."""
    host = name.lower().rstrip(".")
    for pattern in patterns:
        pattern = pattern.lower().rstrip(".")
        if pattern == host:
            return True
        if pattern.startswith("*.") and "." in host and host.split(".", 1)[1] == pattern[2:] and "*" not in pattern[2:]:
            return True
    return False


def describe_certificate(der: bytes, sni: str) -> dict:
    """The fields of a DER certificate that the rules and the report use. Names are server-supplied text: cleaned and capped."""
    cert = x509.load_der_x509_certificate(der)
    names: list[str] = []
    try:
        extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(n) for n in extension.get_values_for_type(x509.DNSName)]
        names += [str(ip) for ip in extension.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass
    common = [a.value for a in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)]
    dns_names = [n for n in names if not _is_ip(n)] or [str(c) for c in common]  # no SAN: the CN is all there is
    return {
        "subject": clean_text(cert.subject.rfc4514_string(), 300),
        "san": [clean_text(n, 255) for n in names[:MAX_SAN]],
        "issuer": clean_text(cert.issuer.rfc4514_string(), 300),
        "not_before": cert.not_valid_before_utc.replace(tzinfo=None).isoformat(timespec="seconds"),
        "not_after": cert.not_valid_after_utc.replace(tzinfo=None).isoformat(timespec="seconds"),
        "self_signed": cert.issuer == cert.subject,
        "hostname_match": hostname_matches(sni, dns_names) if sni else None,
    }


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _reason(exc: BaseException) -> str:
    if isinstance(exc, ssl.SSLError):
        return clean_text(getattr(exc, "reason", None) or (exc.args[-1] if exc.args else type(exc).__name__), 80)
    if isinstance(exc, asyncio.TimeoutError):
        return "timeout"
    if isinstance(exc, ConnectionError):
        return "connection reset or closed"
    return clean_text(type(exc).__name__, 60)


def handshake_request(ip: str, port: int, sni: str | None) -> str:
    return f"TLS HANDSHAKE {ip}:{port} sni={sni or '-'}"


async def tls_handshake(ip: str, port: int, sni: str | None, *, limits: Limits, budget: Budget, relax: frozenset[str] = frozenset()) -> Evidence | None:
    """One handshake with SNI `sni` (the in-scope name asked for). None when the connection cap is reached."""
    request = handshake_request(ip, port, sni)
    try:
        reader, writer = await connect(ip, port, limits=limits, budget=budget, relax=relax)
    except BudgetSpent:
        return None
    except ProbeRefused:
        raise
    except (OSError, asyncio.TimeoutError) as exc:
        return Evidence.create("tls", request, json.dumps({"handshake": "failed", "detail": f"connection: {_reason(exc)}", "sni": sni or ""}, sort_keys=True))
    try:
        await asyncio.wait_for(writer.start_tls(client_context(), server_hostname=sni), limits.handshake_timeout)
        ssl_object = writer.get_extra_info("ssl_object")
        payload = {"handshake": "ok", "sni": sni or "", "protocol": ssl_object.version() or "", "cipher": (ssl_object.cipher() or ("",))[0]}
        der = ssl_object.getpeercert(True)
        payload.update(describe_certificate(der, sni or "") if der else {})
    except (ssl.SSLError, OSError, asyncio.TimeoutError, ValueError) as exc:
        payload = {"handshake": "failed", "detail": _reason(exc), "sni": sni or ""}
    finally:
        await close(writer)
    return Evidence.create("tls", request, json.dumps(payload, sort_keys=True))


def legacy_request(ip: str, port: int, version: str) -> str:
    return f"TLS LEGACY {ip}:{port} {version}"


_SELF_TEST: dict[str, bool] = {}


def _throwaway_certificate() -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
    )


async def can_offer(version: str) -> bool:
    """Can this machine's TLS library offer `version` at all? Found out once per process by a handshake against an in-process
    server on a loopback socket (no target is involved, and it does not count against the budget). When it cannot, a legacy
    probe says `unsupported` instead of mistaking the local limit for the target's refusal."""
    if version in _SELF_TEST:
        return _SELF_TEST[version]
    ok = False
    server = None
    try:
        import os
        import tempfile

        cert_pem, key_pem = _throwaway_certificate()
        with tempfile.TemporaryDirectory() as folder:
            cert_path, key_path = os.path.join(folder, "c.pem"), os.path.join(folder, "k.pem")
            with open(cert_path, "wb") as handle:
                handle.write(cert_pem)
            with open(key_path, "wb") as handle:
                handle.write(key_pem)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.set_ciphers("ALL:@SECLEVEL=0")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                context.minimum_version = context.maximum_version = LEGACY[version]
            context.load_cert_chain(cert_path, key_path)

        async def handle(reader, writer):
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=context)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port, ssl=client_context(low=LEGACY[version]), server_hostname=None), 3)
        ok = (writer.get_extra_info("ssl_object").version() or "").replace("TLSv1.0", "TLSv1") == version
        writer.close()
    except (ssl.SSLError, ValueError, OSError, asyncio.TimeoutError, AttributeError):
        ok = False
    finally:
        if server is not None:
            server.close()
    _SELF_TEST[version] = ok
    return ok


async def legacy_probe(ip: str, port: int, version: str, sni: str | None, *, limits: Limits, budget: Budget, relax: frozenset[str] = frozenset()) -> Evidence | None:
    """Does the server complete a handshake restricted to `version` (TLSv1 or TLSv1.1)? None when the cap is reached."""
    request = legacy_request(ip, port, version)

    def evidence(result: str, detail: str = "") -> Evidence:
        payload = {"result": result, "version": version}
        if detail:
            payload["detail"] = detail
        return Evidence.create("tls", request, json.dumps(payload, sort_keys=True))

    if not await can_offer(version):
        return evidence("unsupported", "this machine's TLS library cannot offer the protocol; nothing is concluded about the server")
    try:
        reader, writer = await connect(ip, port, limits=limits, budget=budget, relax=relax)
    except BudgetSpent:
        return None
    except ProbeRefused:
        raise
    except (OSError, asyncio.TimeoutError) as exc:
        return evidence("error", f"connection: {_reason(exc)}")
    try:
        await asyncio.wait_for(writer.start_tls(client_context(low=LEGACY[version]), server_hostname=sni), limits.handshake_timeout)
        return evidence("accepted", clean_text(writer.get_extra_info("ssl_object").version() or "", 20))
    except ssl.SSLError as exc:
        return evidence("refused", _reason(exc))
    except (OSError, asyncio.TimeoutError, ValueError) as exc:
        # a server that drops the connection on an old ClientHello refuses it just the same; a timeout says nothing
        return evidence("refused" if isinstance(exc, ConnectionError) else "error", _reason(exc))
    finally:
        await close(writer)
