"""A minimal, read-only PostgreSQL wire-protocol client: enough to run one query against crt.sh's public database.

crt.sh publishes direct read access to its certificate database (`psql -h crt.sh -p 5432 -U guest certwatch`), the same
data its web search serves. Its web front end often answers 502 under load while the database answers, so the crt.sh
module asks the database when the web search fails. Scrutator depends on no database driver: this speaks protocol 3.0
(startup, trust authentication, one simple query, terminate) and nothing else. It refuses any authentication request
(the guest account needs none, and no password is ever sent), any server it was not built for, and answers past a size
cap. The connection is plain TCP, like `psql` without TLS: the data is public, and the evidence record holds what came
back, hashed, like any other.
"""

from __future__ import annotations

import asyncio
import struct

MAX_BYTES = 8 * 1024 * 1024  # a whole answer, all rows together
MAX_ROWS = 20_000


class PgError(Exception):
    """The server refused, failed or said something this client does not speak."""


def _startup(user: str, database: str) -> bytes:
    params = b"".join(f"{k}\0{v}\0".encode() for k, v in (("user", user), ("database", database), ("application_name", "scrutator")))
    body = struct.pack("!I", 196608) + params + b"\0"
    return struct.pack("!I", len(body) + 4) + body


def _error_text(payload: bytes) -> str:
    fields = {}
    for part in payload.split(b"\0"):
        if part:
            fields[chr(part[0])] = part[1:].decode("utf-8", "replace")
    return fields.get("M", "server error") + (f" ({fields['C']})" if "C" in fields else "")


async def _read_message(reader: asyncio.StreamReader) -> tuple[bytes, bytes]:
    head = await reader.readexactly(5)
    kind, length = head[:1], struct.unpack("!I", head[1:])[0]
    if length < 4 or length > MAX_BYTES:
        raise PgError(f"message of {length} bytes refused")
    return kind, await reader.readexactly(length - 4)


async def query(host: str, sql: str, *, port: int = 5432, user: str = "guest", database: str = "certwatch",
                timeout: float = 30.0, allow=None) -> tuple[list[str], list[list[str | None]]]:
    """Run one read-only query. Returns (column names, rows of text values).

    The endpoint must pass the egress policy for raw TCP (`scrutator.egress.check_tcp`: crt.sh:5432 only) before any
    connection is opened. `allow` replaces that check, for the tests' local fixture server only."""
    from scrutator.egress import check_tcp

    (allow or check_tcp)(host, port)

    async def go():
        reader, writer = await asyncio.open_connection(host, port)
        try:
            writer.write(_startup(user, database))
            await writer.drain()
            while True:  # authentication and session set-up
                kind, payload = await _read_message(reader)
                if kind == b"R":
                    if struct.unpack("!I", payload[:4])[0] != 0:
                        raise PgError("the server asked for a password; only password-less public access is used")
                elif kind == b"E":
                    raise PgError(_error_text(payload))
                elif kind == b"Z":
                    break
                elif kind not in (b"S", b"K", b"N"):
                    raise PgError(f"unexpected message {kind!r} during start-up")
            body = sql.encode("utf-8") + b"\0"
            writer.write(b"Q" + struct.pack("!I", len(body) + 4) + body)
            await writer.drain()
            columns: list[str] = []
            rows: list[list[str | None]] = []
            total = 0
            failure = None
            while True:
                kind, payload = await _read_message(reader)
                total += len(payload)
                if total > MAX_BYTES:
                    raise PgError(f"answer larger than {MAX_BYTES} bytes")
                if kind == b"T":
                    count = struct.unpack("!H", payload[:2])[0]
                    pos, columns = 2, []
                    for _ in range(count):
                        end = payload.index(b"\0", pos)
                        columns.append(payload[pos:end].decode("utf-8", "replace"))
                        pos = end + 1 + 18
                elif kind == b"D":
                    count = struct.unpack("!H", payload[:2])[0]
                    pos, row = 2, []
                    for _ in range(count):
                        size = struct.unpack("!i", payload[pos:pos + 4])[0]
                        pos += 4
                        if size < 0:
                            row.append(None)
                        else:
                            row.append(payload[pos:pos + size].decode("utf-8", "replace"))
                            pos += size
                    rows.append(row)
                    if len(rows) > MAX_ROWS:
                        raise PgError(f"more than {MAX_ROWS} rows")
                elif kind == b"E":
                    failure = PgError(_error_text(payload))
                elif kind == b"Z":
                    break
                elif kind not in (b"C", b"N", b"S", b"I"):
                    raise PgError(f"unexpected message {kind!r}")
            if failure is not None:
                raise failure
            return columns, rows
        finally:
            try:
                writer.write(b"X\0\0\0\4")
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), 2)
            except Exception:  # noqa: BLE001 - closing is best effort
                pass

    return await asyncio.wait_for(go(), timeout)
