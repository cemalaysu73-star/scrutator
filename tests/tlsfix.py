"""Throwaway certificates and local TLS servers for the active-confirmation tests. Every certificate is generated here, in the
test, and signed by its own key; nothing is read from disk or the network."""

import asyncio
import datetime
import os
import ssl
import tempfile
import warnings

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def make_cert(common_name="example.com", sans=("example.com",), *, not_before_days=-30, not_after_days=90, issuer_cn=None):
    """(cert PEM, key PEM). Validity is relative to now, in days (negative: in the past)."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)])
    issuer = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, issuer_cn)]) if issuer_cn else subject
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=not_before_days))
        .not_valid_after(now + datetime.timedelta(days=not_after_days))
    )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    cert = builder.sign(key, hashes.SHA256())
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
    )


def server_context(cert_key, *, low=None, high=None) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if low is not None:
        context.set_ciphers("ALL:@SECLEVEL=0")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = low
            context.maximum_version = high or low
    cert_pem, key_pem = cert_key
    with tempfile.TemporaryDirectory() as folder:
        cert_path, key_path = os.path.join(folder, "c.pem"), os.path.join(folder, "k.pem")
        with open(cert_path, "wb") as handle:
            handle.write(cert_pem)
        with open(key_path, "wb") as handle:
            handle.write(key_pem)
        context.load_cert_chain(cert_path, key_path)
    return context


async def tls_server(cert_key, *, low=None, high=None, on_connect=None):
    """A local TLS server that completes the handshake and closes. Returns (server, port)."""

    async def handle(reader, writer):
        if on_connect:
            on_connect()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=server_context(cert_key, low=low, high=high))
    return server, server.sockets[0].getsockname()[1]
