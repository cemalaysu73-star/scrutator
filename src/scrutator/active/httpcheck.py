"""HTTP posture: ONE `GET /` per (in-scope name, address, port), on ports 80 (plain) and 443 (TLS) only.

The request is fixed: `GET / HTTP/1.1`, `Host: <the in-scope name>`, the generic User-Agent `Scrutator/<version> (authorised
review)`, `Accept: */*`, `Connection: close`. No cookies, no credentials, no query string, no second request. A redirect is
recorded (status and Location) and NEVER followed: a redirect to another host, or another port, is not visited.
At most 16 KiB are read (the status line and headers; the body is not read), a response that is not HTTP is recorded as that,
and only a fixed list of headers is stored, each cleaned of control characters and cut to 300 characters.
"""

from __future__ import annotations

import asyncio
import json
import re

from scrutator.active import USER_AGENT
from scrutator.active.guard import Budget, Limits
from scrutator.active.net import BudgetSpent, ProbeRefused, clean_text, close, connect
from scrutator.active.tlscheck import _reason, client_context
from scrutator.model import Evidence

MAX_RESPONSE = 16 * 1024
MAX_HEADERS = 100
KEPT_HEADERS = (
    "server", "x-powered-by", "strict-transport-security", "content-security-policy", "x-frame-options",
    "x-content-type-options", "referrer-policy", "location", "content-type",
)
_NAME = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
_STATUS = re.compile(r"^HTTP/(\d\.\d) (\d{3})(?: (.*))?$")


def request_bytes(name: str) -> bytes:
    if not _NAME.match(name):
        raise ProbeRefused(f"{name!r} is not a host name this probe will put in a request")
    return (
        f"GET / HTTP/1.1\r\nHost: {name}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    ).encode("ascii")


def request_label(ip: str, port: int, name: str, tls: bool) -> str:
    return f"HTTP GET {'https' if tls else 'http'}://{name}/ via {ip}:{port}"


def parse_head(raw: bytes) -> dict:
    """The recorded summary of a response head: status, reason, and the kept headers. Everything is untrusted text."""
    head, _, _ = raw.partition(b"\r\n\r\n")
    lines = head.decode("utf-8", "replace").split("\r\n")
    match = _STATUS.match(lines[0].strip()) if lines else None
    if not match:
        return {"status": 0, "error": "the answer is not an HTTP response", "bytes_read": len(raw)}
    kept: dict[str, str] = {}
    for line in lines[1 : 1 + MAX_HEADERS]:
        key, colon, value = line.partition(":")
        key = key.strip().lower()
        if colon and key in KEPT_HEADERS:
            text = clean_text(value, 300)
            kept[key] = f"{kept[key]}, {text}"[:300] if key in kept else text
    payload = {"status": int(match.group(2)), "reason": clean_text(match.group(3) or "", 60), "http_version": match.group(1), "headers": kept, "bytes_read": len(raw)}
    if len(lines) - 1 > MAX_HEADERS:
        payload["headers_cut"] = True
    return payload


async def read_head(reader: asyncio.StreamReader) -> tuple[bytes, bool]:
    """Bytes of the response up to the end of the headers or MAX_RESPONSE, whichever comes first, and whether the cap cut it."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = await reader.read(MAX_RESPONSE - len(data))
        if not chunk:
            break
        data += chunk
        if len(data) >= MAX_RESPONSE:
            return data, b"\r\n\r\n" not in data
    return data, False


async def http_get(ip: str, port: int, name: str, tls: bool, *, limits: Limits, budget: Budget, relax: frozenset[str] = frozenset()) -> Evidence | None:
    """The one request. None when the connection cap is reached."""
    request = request_bytes(name)  # refused before any connection when the name is not a plain host name
    label = request_label(ip, port, name, tls)

    def evidence(payload: dict) -> Evidence:
        return Evidence.create("http", label, json.dumps({"name": name, "scheme": "https" if tls else "http", **payload}, sort_keys=True))

    try:
        reader, writer = await connect(ip, port, limits=limits, budget=budget, relax=relax)
    except BudgetSpent:
        return None
    except ProbeRefused:
        raise
    except (OSError, asyncio.TimeoutError) as exc:
        return evidence({"status": 0, "error": f"connection: {_reason(exc)}"})

    async def exchange() -> dict:
        if tls:
            await writer.start_tls(client_context(), server_hostname=name)
        writer.write(request)
        await writer.drain()
        raw, cut = await read_head(reader)
        payload = parse_head(raw)
        if cut:
            payload["headers_cut"] = True
        return payload

    try:
        payload = await asyncio.wait_for(exchange(), limits.http_timeout)
    except asyncio.TimeoutError:
        payload = {"status": 0, "error": "timeout"}
    except (OSError, ValueError) as exc:  # includes ssl.SSLError
        payload = {"status": 0, "error": _reason(exc)}
    finally:
        await close(writer)
    return evidence(payload)
