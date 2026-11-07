"""`--proxy`: one outbound proxy for the HTTP sources, the opt-in web client, the crt.sh fallback and the active probes.
Every proxy here is a local fixture on 127.0.0.1; nothing leaves the machine."""

import asyncio
import importlib.util
import struct

import pytest
from typer.testing import CliRunner

from scrutator import cli, proxy
from scrutator.context import open_context
from scrutator.proxy import ProxyError, TunnelError, open_tcp, parse_proxy


@pytest.fixture(autouse=True)
def reset_proxy():
    proxy.set_proxy(None)
    yield
    proxy.set_proxy(None)


async def echo_server():
    async def handle(reader, writer):
        data = await reader.read(100)
        writer.write(b"echo:" + data)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def connect_proxy(status="200 Connection established", seen=None):
    """An HTTP proxy that tunnels CONNECT to the real target (or answers `status` when it is not 200)."""

    async def handle(reader, writer):
        head = b""
        while b"\r\n\r\n" not in head:
            head += await reader.read(1024)
        if seen is not None:
            seen.append(head.decode("latin-1"))
        if not status.startswith("200"):
            writer.write(f"HTTP/1.1 {status}\r\n\r\n".encode())
            await writer.drain()
            writer.close()
            return
        target = head.split(b" ", 2)[1].decode()
        host, _, port = target.rpartition(":")
        up_r, up_w = await asyncio.open_connection(host, int(port))
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()

        async def pipe(src, dst):
            try:
                while data := await src.read(4096):
                    dst.write(data)
                    await dst.drain()
            except ConnectionError:
                pass
            finally:
                dst.close()

        await asyncio.gather(pipe(reader, up_w), pipe(up_r, writer))

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def socks_proxy(reply=0, seen=None):
    """A SOCKS5 proxy (no auth, or user/password) that tunnels to the real target or answers `reply`."""

    async def handle(reader, writer):
        greeting = await reader.readexactly(2)
        methods = await reader.readexactly(greeting[1])
        if 2 in methods:
            writer.write(b"\x05\x02")
            await reader.readexactly(1)
            user = await reader.readexactly((await reader.readexactly(1))[0])
            password = await reader.readexactly((await reader.readexactly(1))[0])
            if seen is not None:
                seen.append(("auth", user.decode(), password.decode()))
            writer.write(b"\x01\x00")
        else:
            writer.write(b"\x05\x00")
        head = await reader.readexactly(4)
        if head[3] == 1:
            host = ".".join(str(b) for b in await reader.readexactly(4))
            kind = "ip"
        elif head[3] == 3:
            host = (await reader.readexactly((await reader.readexactly(1))[0])).decode()
            kind = "name"
        else:
            host, kind = (await reader.readexactly(16)).hex(), "ip6"
        port = struct.unpack("!H", await reader.readexactly(2))[0]
        if seen is not None:
            seen.append((kind, host, port))
        if reply:
            writer.write(bytes([5, reply, 0, 1]) + b"\0\0\0\0\0\0")
            await writer.drain()
            writer.close()
            return
        up_r, up_w = await asyncio.open_connection("127.0.0.1" if kind == "name" else host, port)
        writer.write(b"\x05\x00\x00\x01\0\0\0\0\0\0")
        await writer.drain()

        async def pipe(src, dst):
            try:
                while data := await src.read(4096):
                    dst.write(data)
                    await dst.drain()
            except ConnectionError:
                pass
            finally:
                dst.close()

        await asyncio.gather(pipe(reader, up_w), pipe(up_r, writer))

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


def test_parse_proxy_accepts_the_three_schemes_and_hides_credentials():
    spec = parse_proxy("socks5h://user:p%40ss@127.0.0.1:9050")
    assert (spec.scheme, spec.host, spec.port, spec.username, spec.password) == ("socks5h", "127.0.0.1", 9050, "user", "p@ss")
    assert spec.label() == "socks5h://127.0.0.1:9050" and "p@ss" not in spec.label() and "user" not in spec.label()
    assert parse_proxy("http://proxy.example.net:3128").url() == "http://proxy.example.net:3128"


@pytest.mark.parametrize("bad", ["", "ftp://x:1", "socks4://x:1", "http://x", "http://:80", "127.0.0.1:9050", "http://x:80/path", "http://x:80?q=1", "http://x y:80"])
def test_parse_proxy_refuses_unusable_urls(bad):
    with pytest.raises(ProxyError):
        parse_proxy(bad)


async def test_http_connect_tunnel_carries_a_connection_and_sends_credentials():
    echo, echo_port = await echo_server()
    seen: list = []
    server, port = await connect_proxy(seen=seen)
    try:
        spec = parse_proxy(f"http://alice:secret@127.0.0.1:{port}")
        reader, writer = await open_tcp("127.0.0.1", echo_port, timeout=3, proxy=spec)
        writer.write(b"hi")
        await writer.drain()
        assert await reader.read(100) == b"echo:hi"
        writer.close()
        assert seen[0].startswith(f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1")
        assert "Proxy-Authorization: Basic" in seen[0]
    finally:
        server.close()
        echo.close()


@pytest.mark.parametrize("status,kind", [("403 Forbidden", "proxy"), ("407 Proxy Authentication Required", "proxy"),
                                          ("502 Bad Gateway", "unreachable"), ("504 Gateway Timeout", "timeout")])
async def test_http_connect_failures_are_classified(status, kind):
    server, port = await connect_proxy(status=status)
    try:
        with pytest.raises(TunnelError) as caught:
            await open_tcp("192.0.2.1", 23, timeout=3, proxy=parse_proxy(f"http://127.0.0.1:{port}"))
        assert caught.value.kind == kind
    finally:
        server.close()


async def test_socks5_tunnel_with_ip_name_and_credentials():
    echo, echo_port = await echo_server()
    seen: list = []
    server, port = await socks_proxy(seen=seen)
    try:
        # an address is sent as an address
        reader, writer = await open_tcp("127.0.0.1", echo_port, timeout=3, proxy=parse_proxy(f"socks5://127.0.0.1:{port}"))
        writer.write(b"a")
        await writer.drain()
        assert await reader.read(100) == b"echo:a"
        writer.close()
        # socks5h hands the proxy the name; socks5 resolves it here and sends an address
        reader, writer = await open_tcp("localhost", echo_port, timeout=3, proxy=parse_proxy(f"socks5h://u:p@127.0.0.1:{port}"))
        writer.close()
        assert ("auth", "u", "p") in seen and ("name", "localhost", echo_port) in seen
        seen.clear()
        reader, writer = await open_tcp("localhost", echo_port, timeout=3, proxy=parse_proxy(f"socks5://127.0.0.1:{port}"))
        writer.close()
        assert seen[0][0] in ("ip", "ip6")
    finally:
        server.close()
        echo.close()


@pytest.mark.parametrize("reply,kind", [(5, "refused"), (4, "unreachable"), (3, "unreachable"), (6, "timeout"), (2, "proxy")])
async def test_socks5_replies_are_classified(reply, kind):
    server, port = await socks_proxy(reply=reply)
    try:
        with pytest.raises(TunnelError) as caught:
            await open_tcp("192.0.2.1", 23, timeout=3, proxy=parse_proxy(f"socks5://127.0.0.1:{port}"))
        assert caught.value.kind == kind
    finally:
        server.close()


async def test_a_proxy_that_is_down_is_a_proxy_failure_not_a_target_answer():
    server, port = await socks_proxy()
    server.close()
    await server.wait_closed()
    with pytest.raises(TunnelError) as caught:
        await open_tcp("192.0.2.1", 23, timeout=3, proxy=parse_proxy(f"socks5://127.0.0.1:{port}"))
    assert caught.value.kind == "proxy"


async def test_the_http_sources_go_through_the_proxy_and_nowhere_else():
    seen: list = []
    server, port = await connect_proxy(status="403 Forbidden", seen=seen)
    try:
        proxy.set_proxy(f"http://127.0.0.1:{port}")
        async with open_context() as ctx:
            with pytest.raises(Exception):
                await ctx.http.get("https://crt.sh/?q=example.com&output=json")
        assert seen and seen[0].startswith("CONNECT crt.sh:443 ")
    finally:
        server.close()


async def test_the_crtsh_fallback_connection_goes_through_the_proxy():
    from scrutator import pgwire

    seen: list = []
    server, port = await connect_proxy(status="403 Forbidden", seen=seen)
    try:
        proxy.set_proxy(f"http://127.0.0.1:{port}")
        with pytest.raises(TunnelError):
            await pgwire.query("crt.sh", "select 1", port=5432, allow=lambda h, p: None, timeout=3)
        assert seen[0].startswith("CONNECT crt.sh:5432 ")
    finally:
        server.close()


async def test_the_web_client_uses_the_proxy():
    from scrutator.web import open_web, scope_guard
    from scrutator.scope import ScopePolicy

    seen: list = []
    server, port = await connect_proxy(status="403 Forbidden", seen=seen)
    try:
        proxy.set_proxy(f"http://127.0.0.1:{port}")
        async with open_web(scope_guard(ScopePolicy(domains=["example.com"]), resolve=_public)) as web:
            with pytest.raises(Exception):
                await web.get("https://example.com/")
        assert seen and seen[0].startswith("CONNECT example.com:443 ")
    finally:
        server.close()


async def _public(host):
    return ["93.184.216.34"]


@pytest.mark.skipif(importlib.util.find_spec("socksio") is not None, reason="socksio is installed")
def test_a_socks_proxy_for_the_http_sources_needs_the_extra_and_says_so():
    with pytest.raises(ProxyError, match="socksio"):
        proxy.set_proxy("socks5h://127.0.0.1:9050")


def test_the_cli_refuses_a_bad_proxy_and_never_prints_credentials():
    runner = CliRunner()
    result = runner.invoke(cli.app, ["--proxy", "ftp://user:hunter2@127.0.0.1:1", "sources"])
    assert result.exit_code == 2 and "scheme" in result.output
    assert "hunter2" not in result.output
    result = runner.invoke(cli.app, ["--proxy", "http://user:hunter2@127.0.0.1:1", "sources"])
    assert result.exit_code == 0 and "hunter2" not in result.output and "http://127.0.0.1:1" in result.output
    assert "DNS lookups do not" in result.output


def test_the_environment_variable_sets_the_proxy(monkeypatch):
    monkeypatch.setenv("SCRUTATOR_PROXY", "http://127.0.0.1:3128")
    result = CliRunner().invoke(cli.app, ["sources"])
    assert result.exit_code == 0 and proxy.current().port == 3128
