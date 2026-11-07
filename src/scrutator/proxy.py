"""One outbound proxy for everything Scrutator sends: `scrutator --proxy URL ...` (or `SCRUTATOR_PROXY`).

Journalists, researchers and responders often must not reach a target or a data source from their own address. A single
proxy setting is used by

- every HTTP request of the data sources (httpx: `http://` proxies always, `socks5://` / `socks5h://` when the
  `socks` extra is installed: `pip install "scrutator[socks]"`),
- the web client of the opt-in modules (brand, organisation exposure),
- the one raw TCP connection of the crt.sh fallback (`pgwire`), and
- every connection of the active confirmation probes (`scrutator audit --active`), through a small built-in tunnel:
  HTTP `CONNECT` or SOCKS5 (no extra package).

What a proxy does not hide, said plainly:

- **DNS.** Name lookups are made by the local resolver (dnspython), not through the proxy: the resolver and the
  target's own name servers see your address and every name asked about. Run Scrutator inside a network namespace, VPN
  or DNS-forwarding setup if that matters. Names are never sent to the proxy by the DNS path.
- **Names inside the tunnel.** `socks5h://` and an HTTP proxy are given the host name of a data source (the proxy resolves
  it); `socks5://` is given an address resolved locally. Active probes always connect to an IP address.
- **What the proxy changes.** Through a proxy, "closed" means the proxy reported a refusal, and "filtered" means it
  timed out or reported the host unreachable; a proxy that blocks a port looks like a filtered port. The probe evidence
  records that a proxy was used (its host and port, never its credentials).
- The proxy operator sees the destinations. Credentials in the URL (`user:password@`) are held in memory only and are
  redacted from every output; prefer the environment variable to a command-line argument that lands in shell history.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import struct
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

SCHEMES = ("http", "socks5", "socks5h")
MAX_HEAD = 8192


class ProxyError(ValueError):
    """The proxy setting is unusable."""


class TunnelError(OSError):
    """A proxy could not open the connection asked for. `kind` is `refused` (the target refused), `unreachable`,
    `timeout` or `proxy` (the proxy itself refused, failed or answered something unexpected)."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class ProxySpec:
    scheme: str
    host: str
    port: int
    username: str = ""
    password: str = ""

    def url(self) -> str:
        auth = ""
        if self.username or self.password:
            from urllib.parse import quote

            auth = f"{quote(self.username, safe='')}:{quote(self.password, safe='')}@"
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{auth}{host}:{self.port}"

    def label(self) -> str:
        """What may be logged: scheme, host and port, never credentials."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}:{self.port}"


def parse_proxy(text: str) -> ProxySpec:
    """A proxy URL as a `ProxySpec`, or ProxyError. `http://host:port`, `socks5://host:port`, `socks5h://host:port`,
    optionally with `user:password@`."""
    raw = str(text).strip()
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError as exc:
        raise ProxyError(f"not a proxy URL: {exc}") from exc
    if parts.scheme not in SCHEMES:
        raise ProxyError(f"the proxy scheme must be one of {', '.join(SCHEMES)} (for example socks5h://127.0.0.1:9050)")
    if not parts.hostname or port is None:
        raise ProxyError("a proxy URL needs a host and a port, for example socks5h://127.0.0.1:9050")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ProxyError("a proxy URL has no path, query or fragment")
    if any(ord(c) < 33 or ord(c) > 126 for c in raw):
        raise ProxyError("a proxy URL has no spaces or control characters")
    return ProxySpec(parts.scheme, parts.hostname, port, unquote(parts.username or ""), unquote(parts.password or ""))


_CURRENT: ProxySpec | None = None


def set_proxy(text: str | None) -> ProxySpec | None:
    """Use this proxy for everything from now on (None: none). Validates before it is stored."""
    global _CURRENT
    if not text:
        _CURRENT = None
        return None
    spec = parse_proxy(text)
    if spec.scheme.startswith("socks"):
        try:
            import socksio  # noqa: F401
        except ImportError:
            # the built-in tunnel (active probes, crt.sh) needs nothing, but the HTTP sources go through httpx
            raise ProxyError(
                "a SOCKS proxy for the HTTP data sources needs the optional package socksio: pip install 'scrutator[socks]'"
            ) from None
    _CURRENT = spec
    return spec


def current() -> ProxySpec | None:
    return _CURRENT


def httpx_proxy():
    """The `httpx.Proxy` for HTTP clients, or None."""
    if _CURRENT is None:
        return None
    import httpx

    return httpx.Proxy(_CURRENT.url())


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


async def _read_head(reader: asyncio.StreamReader) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = await reader.read(1024)
        if not chunk:
            raise TunnelError("proxy", "the proxy closed the connection")
        data += chunk
        if len(data) > MAX_HEAD:
            raise TunnelError("proxy", "the proxy's answer is too long")
    return data


async def _http_connect(spec: ProxySpec, reader, writer, host: str, port: int) -> None:
    target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}", "Proxy-Connection: keep-alive"]
    if spec.username or spec.password:
        token = base64.b64encode(f"{spec.username}:{spec.password}".encode()).decode()
        lines.append(f"Proxy-Authorization: Basic {token}")
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
    await writer.drain()
    head = await _read_head(reader)
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1")
    parts = status_line.split()
    try:
        status = int(parts[1])
    except (IndexError, ValueError):
        raise TunnelError("proxy", "the proxy did not answer with an HTTP status") from None
    if status == 200:
        return
    if status == 504:
        raise TunnelError("timeout", f"the proxy reported a gateway timeout ({status})")
    if status in (502, 503):
        raise TunnelError("unreachable", f"the proxy could not reach the target ({status})")
    raise TunnelError("proxy", f"the proxy refused the tunnel (HTTP {status})")


_SOCKS_REPLIES = {
    1: ("proxy", "general SOCKS server failure"),
    2: ("proxy", "connection not allowed by the proxy's ruleset"),
    3: ("unreachable", "network unreachable"),
    4: ("unreachable", "host unreachable"),
    5: ("refused", "connection refused"),
    6: ("timeout", "TTL expired"),
    7: ("proxy", "command not supported"),
    8: ("proxy", "address type not supported"),
}


async def _socks5(spec: ProxySpec, reader, writer, host: str, port: int) -> None:
    auth = bool(spec.username or spec.password)
    writer.write(b"\x05\x02\x00\x02" if auth else b"\x05\x01\x00")
    await writer.drain()
    reply = await reader.readexactly(2)
    if reply[0] != 5:
        raise TunnelError("proxy", "not a SOCKS5 proxy")
    if reply[1] == 2:
        user, password = spec.username.encode()[:255], spec.password.encode()[:255]
        writer.write(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
        await writer.drain()
        if (await reader.readexactly(2))[1] != 0:
            raise TunnelError("proxy", "the SOCKS5 proxy refused the credentials")
    elif reply[1] != 0:
        raise TunnelError("proxy", "the SOCKS5 proxy accepts no method this tool offers")
    if _is_ip(host):
        address = ipaddress.ip_address(host.strip("[]"))
        body = (b"\x01" if address.version == 4 else b"\x04") + address.packed
    else:
        name = host.encode("idna")
        if len(name) > 255:
            raise TunnelError("proxy", "host name too long for SOCKS5")
        body = b"\x03" + bytes([len(name)]) + name
    writer.write(b"\x05\x01\x00" + body + struct.pack("!H", port))
    await writer.drain()
    head = await reader.readexactly(4)
    if head[0] != 5:
        raise TunnelError("proxy", "not a SOCKS5 proxy")
    if head[1] != 0:
        kind, text = _SOCKS_REPLIES.get(head[1], ("proxy", f"SOCKS5 reply {head[1]}"))
        raise TunnelError(kind, f"the proxy reported: {text}")
    skip = {1: 4, 4: 16}.get(head[3])
    if skip is None:
        skip = (await reader.readexactly(1))[0] if head[3] == 3 else 0
    await reader.readexactly(skip + 2)


async def open_tcp(host: str, port: int, *, timeout: float, proxy: ProxySpec | None = None):
    """A connected (reader, writer): direct, or through the configured proxy. Raises OSError (a `TunnelError` carrying
    a `kind` when a proxy was involved) or asyncio.TimeoutError within `timeout` seconds in all."""
    spec = proxy if proxy is not None else _CURRENT
    if spec is None:
        return await asyncio.wait_for(asyncio.open_connection(host, port), timeout)

    async def via() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        try:
            reader, writer = await asyncio.open_connection(spec.host, spec.port)
        except OSError as exc:
            raise TunnelError("proxy", f"cannot reach the proxy {spec.label()}: {exc.strerror or exc}") from exc
        try:
            if spec.scheme == "http":
                await _http_connect(spec, reader, writer, host, port)
            else:
                # socks5 resolves locally, socks5h lets the proxy resolve; an address is sent as an address either way
                target = host
                if spec.scheme == "socks5" and not _is_ip(host):
                    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=1)
                    infos.sort(key=lambda info: info[0] != 2)  # an IPv4 address first
                    target = infos[0][4][0]
                await _socks5(spec, reader, writer, target, port)
        except (asyncio.IncompleteReadError, ConnectionError) as exc:
            writer.close()
            raise TunnelError("proxy", f"the proxy closed the connection: {type(exc).__name__}") from exc
        except BaseException:
            writer.close()
            raise
        return reader, writer

    return await asyncio.wait_for(via(), timeout)
