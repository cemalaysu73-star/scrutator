"""TCP connect check and read-only banner capture.

One connection per (address, port). The outcome is `open` (the handshake completed), `closed` (the host answered with a
refusal) or `filtered` (no answer in time, or the network said unreachable). On an open port the probe only listens:
it sends nothing, waits up to `banner_timeout` seconds and keeps at most 256 bytes, then closes. A server that sends a
banner on connect (SSH, FTP, SMTP, Telnet option negotiation) shows it; one that waits for the client (HTTP) shows none.

Never sent: a login, a command, a probe string, a protocol greeting.
"""

from __future__ import annotations

import asyncio
import json
import time

from scrutator.active import MAX_BANNER
from scrutator.active.guard import Budget, Limits
from scrutator.active.net import BudgetSpent, ProbeRefused, clean_text, close, connect
from scrutator.model import Evidence
from scrutator.proxy import TunnelError

IDLE_AFTER_DATA = 0.25  # once something arrived, wait this long for more (a banner ends with a newline or a pause)
_REFUSED_WINERRORS = (1225, 10061)
_IAC = 0xFF


def telnet_text(raw: bytes) -> tuple[bytes, bool]:
    """`raw` without Telnet IAC option negotiation (IAC DO/DONT/WILL/WONT <option>, IAC SB ... IAC SE, IAC IAC), and whether
    any was present. A Telnet server opens with negotiation bytes that are not text."""
    out, i, seen = bytearray(), 0, False
    while i < len(raw):
        if raw[i] != _IAC:
            out.append(raw[i])
            i += 1
            continue
        seen = True
        if i + 1 < len(raw) and raw[i + 1] == _IAC:
            out.append(_IAC)
            i += 2
        elif i + 1 < len(raw) and raw[i + 1] == 250:  # SB ... IAC SE
            end = raw.find(bytes([_IAC, 240]), i + 2)
            i = len(raw) if end < 0 else end + 2
        else:
            i += 3
    return bytes(out), seen


def banner_text(raw: bytes) -> tuple[str, str]:
    """(sanitised banner, a note about what was not text): control characters and escapes removed, Telnet negotiation dropped."""
    text, negotiated = telnet_text(raw[:MAX_BANNER])
    banner = clean_text(text.decode("utf-8", "replace"), MAX_BANNER)
    if banner:
        return banner, ""
    if negotiated:
        return "", "telnet option negotiation, no text"
    return "", "binary data, no text" if raw else ""


def classify(exc: BaseException, limits: Limits) -> tuple[str, str]:
    """(state, detail) for a failed connection."""
    if isinstance(exc, TunnelError):
        if exc.kind == "refused":
            return "closed", "refused (reported by the proxy)"
        if exc.kind in ("timeout", "unreachable"):
            return "filtered", f"{exc.kind} (reported by the proxy)"
        return "error", f"proxy: {exc}"[:200]
    if isinstance(exc, asyncio.TimeoutError):
        return "filtered", f"no answer within {limits.connect_timeout:g} s"
    if isinstance(exc, ConnectionRefusedError) or getattr(exc, "winerror", None) in _REFUSED_WINERRORS:
        return "closed", "refused"
    if isinstance(exc, ConnectionResetError):
        return "closed", "reset"
    if isinstance(exc, OSError):
        return "filtered", f"unreachable: {exc.strerror or type(exc).__name__}"[:120]
    return "error", type(exc).__name__


async def read_banner(reader: asyncio.StreamReader, limits: Limits) -> bytes:
    """Up to MAX_BANNER bytes the server sends on its own, within `banner_timeout` seconds. Nothing is sent."""
    data = b""
    end = time.monotonic() + limits.banner_timeout
    while len(data) < MAX_BANNER:
        wait = end - time.monotonic()
        if data:
            wait = min(wait, IDLE_AFTER_DATA)
        if wait <= 0:
            break
        try:
            chunk = await asyncio.wait_for(reader.read(MAX_BANNER - len(data)), wait)
        except asyncio.TimeoutError:
            break
        except (ConnectionError, OSError):
            break
        if not chunk:
            break  # the server closed
        data += chunk
        if data.endswith(b"\n"):
            break
    return data


def evidence(ip: str, port: int, payload: dict) -> Evidence:
    return Evidence.create("tcp", f"TCP CONNECT {ip}:{port}", json.dumps(payload, sort_keys=True))


async def tcp_check(ip: str, port: int, *, limits: Limits, budget: Budget, relax: frozenset[str] = frozenset()) -> Evidence | None:
    """One connect check. None when nothing was attempted (the connection cap is reached)."""
    try:
        reader, writer = await connect(ip, port, limits=limits, budget=budget, relax=relax)
    except BudgetSpent:
        return None
    except ProbeRefused:
        raise
    except (OSError, asyncio.TimeoutError) as exc:
        state, detail = classify(exc, limits)
        return evidence(ip, port, {"state": state, "detail": detail})
    try:
        raw = await read_banner(reader, limits)
    finally:
        await close(writer)
    banner, note = banner_text(raw)
    payload = {"state": "open", "banner": banner, "banner_bytes": len(raw)}
    if note:
        payload["banner_note"] = note
    return evidence(ip, port, payload)
