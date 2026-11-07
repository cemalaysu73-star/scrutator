"""The one place an active probe opens a connection, and the text hygiene for what comes back.

`connect` is the lowest layer of the guardrails and does not trust its caller: it refuses an address that is not public
(unless a test relaxed it), a port outside 1..65535, and any connection the budget no longer allows, before a socket is
opened. Everything a server sends is hostile text: it is cut to a few hundred characters and stripped of control and
bidirectional characters before it is stored anywhere.
"""

from __future__ import annotations

import asyncio
import re

from scrutator import proxy as proxy_setting
from scrutator.active.guard import Budget, Limits, refusal
from scrutator.textsafe import strip_unsafe


class ProbeRefused(Exception):
    """The connection was not made: the address or port is not allowed, or the budget is spent."""


class BudgetSpent(ProbeRefused):
    pass


async def connect(ip: str, port: int, *, limits: Limits, budget: Budget, relax: frozenset[str] = frozenset()):
    """A connected (reader, writer) to a public address, direct or through the configured proxy. Raises ProbeRefused (nothing
    opened), OSError or asyncio.TimeoutError (the connection failed: the caller classifies it)."""
    problem = refusal(ip, relax)
    if problem:
        raise ProbeRefused(f"{ip} is refused: {problem}")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ProbeRefused(f"port {port!r} is not a port")
    if not await budget.take():
        raise BudgetSpent(f"the connection cap of {limits.max_connections} is reached")
    return await proxy_setting.open_tcp(ip, port, timeout=limits.connect_timeout)


async def close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), 1.0)
    except (OSError, asyncio.TimeoutError, RuntimeError):
        pass


_SPACE = re.compile(r"\s+")
# a terminal escape sequence (colours, cursor moves, a window-title OSC string) is removed whole, not only its ESC byte
_ESCAPES = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x9b[0-9;?]*[ -/]*[@-~]")


def clean_text(value, limit: int) -> str:
    """Server-supplied text for storage: no control or bidirectional characters, whitespace collapsed to single spaces,
    at most `limit` characters (a trailing ellipsis marks a cut)."""
    text = strip_unsafe(_ESCAPES.sub("", str(value))).replace("�", "?")
    text = _SPACE.sub(" ", text).strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."
