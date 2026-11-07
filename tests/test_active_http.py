"""Active confirmation, task 4: HTTP posture. One GET / per name and port, fixed User-Agent, nothing followed, a few KiB read."""

import asyncio
import json
import re
import time

import pytest

from activefix import FAST, config, make_active_store
from scrutator import __version__, active
from scrutator.active import httpcheck
from scrutator.active.guard import Budget, Limits
from scrutator.active.net import ProbeRefused
from scrutator.active.run import run_active
from scrutator.packs import load_packs
from tlsfix import make_cert, server_context

LOOP = frozenset({"loopback"})
UA = f"Scrutator/{__version__} (authorised review)"


async def http_server(reply, *, record=None, ssl_context=None, after=None):
    """A local HTTP server. `reply` is bytes, or an async function (writer) that writes the answer. Requests are appended to
    `record` (the full request text)."""

    async def handle(reader, writer):
        try:
            data = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            writer.close()
            return
        if record is not None:
            record.append(data.decode("latin-1"))
        try:
            if callable(reply):
                await reply(writer)
            else:
                writer.write(reply)
                await writer.drain()
        except ConnectionError:
            pass
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ssl_context)
    return server, server.sockets[0].getsockname()[1]


async def get(port, name="example.com", tls=False, limits=FAST):
    ev = await httpcheck.http_get("127.0.0.1", port, name, tls, limits=limits, budget=Budget(limits), relax=LOOP)
    return ev, json.loads(ev.payload)


FULL = (
    b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nStrict-Transport-security: max-age=31536000; includeSubDomains\r\n"
    b"Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\nX-Frame-Options: DENY\r\nX-Content-Type-Options: nosniff\r\n"
    b"Referrer-Policy: no-referrer\r\nSet-Cookie: session=abc\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello"
)


async def test_one_fixed_request_and_the_security_headers_are_recorded():
    seen = []
    server, port = await http_server(FULL, record=seen)
    try:
        ev, payload = await get(port)
    finally:
        server.close()
    assert len(seen) == 1
    lines = seen[0].split("\r\n")
    assert lines[0] == "GET / HTTP/1.1" and "Host: example.com" in lines and f"User-Agent: {UA}" in lines
    assert not any(l.lower().startswith(("cookie", "authorization")) for l in lines) and "@" not in seen[0]
    assert ev.source == "http" and ev.request == f"HTTP GET http://example.com/ via 127.0.0.1:{port}"
    assert payload["status"] == 200 and payload["scheme"] == "http" and payload["name"] == "example.com"
    headers = payload["headers"]
    assert headers["strict-transport-security"].startswith("max-age=31536000") and headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff" and headers["referrer-policy"] == "no-referrer"
    assert headers["server"] == "nginx/1.18.0" and "frame-ancestors" in headers["content-security-policy"]
    assert "set-cookie" not in headers  # only a fixed list of headers is kept


async def test_missing_headers_are_simply_absent_from_the_record():
    server, port = await http_server(b"HTTP/1.1 200 OK\r\nServer: Apache\r\nContent-Length: 0\r\n\r\n")
    try:
        _, payload = await get(port)
    finally:
        server.close()
    assert payload["headers"] == {"server": "Apache"}


async def test_a_redirect_is_recorded_and_never_followed():
    visited = []

    async def other(reader, writer):
        visited.append(1)
        writer.close()

    elsewhere = await asyncio.start_server(other, "127.0.0.1", 0)
    eport = elsewhere.sockets[0].getsockname()[1]
    seen = []
    server, port = await http_server(f"HTTP/1.1 301 Moved\r\nLocation: http://127.0.0.1:{eport}/admin\r\n\r\n".encode(), record=seen)
    try:
        _, payload = await get(port)
        await asyncio.sleep(0.2)
    finally:
        server.close()
        elsewhere.close()
    assert payload["status"] == 301 and payload["headers"]["location"] == f"http://127.0.0.1:{eport}/admin"
    assert visited == [] and len(seen) == 1


async def test_https_sends_the_name_as_sni_and_host_and_records_the_response():
    seen = []
    context = server_context(make_cert("example.com", ["example.com"]))
    names = []
    context.sni_callback = lambda sock, name, ctx: names.append(name)
    server, port = await http_server(FULL, record=seen, ssl_context=context)
    try:
        _, payload = await get(port, tls=True)
    finally:
        server.close()
    assert payload["status"] == 200 and payload["scheme"] == "https" and names == ["example.com"] and "Host: example.com" in seen[0]


async def test_a_huge_body_is_not_read_beyond_a_few_kib():
    async def reply(writer):
        writer.write(b"HTTP/1.1 200 OK\r\nServer: big\r\n\r\n")
        for _ in range(20000):  # 20 MB
            writer.write(b"B" * 1000)
            await writer.drain()

    server, port = await http_server(reply)
    try:
        start = time.monotonic()
        _, payload = await get(port)
        elapsed = time.monotonic() - start
    finally:
        server.close()
    assert payload["status"] == 200 and payload["bytes_read"] <= httpcheck.MAX_RESPONSE and elapsed < 2.0


async def test_an_endless_header_block_is_cut_at_the_cap():
    async def reply(writer):
        writer.write(b"HTTP/1.1 200 OK\r\n")
        for i in range(5000):
            writer.write(b"X-Junk-%d: " % i + b"j" * 100 + b"\r\n")
            await writer.drain()

    server, port = await http_server(reply)
    try:
        _, payload = await get(port)
    finally:
        server.close()
    assert payload["bytes_read"] <= httpcheck.MAX_RESPONSE and payload.get("headers_cut") is True and payload["status"] == 200


async def test_hostile_header_values_are_cleaned_and_cut():
    raw = (
        b"HTTP/1.1 200 OK\r\nServer: ev\x1b[31mil\x00\x07\xe2\x80\xaeevil\r\n"
        b"X-Powered-By: " + b"A" * 5000 + b"\r\nReferrer-Policy: a\r\nreferrer-policy: b\r\nContent-Type: text/\x01html\r\n\r\n"
    )
    server, port = await http_server(raw)
    try:
        _, payload = await get(port)
    finally:
        server.close()
    headers = payload["headers"]
    assert headers["server"] == "evilevil" and len(headers["x-powered-by"]) == 300 and headers["x-powered-by"].endswith("...")
    assert headers["referrer-policy"] == "a, b" and headers["content-type"] == "text/html"


async def test_a_response_that_is_not_http_is_recorded_as_that():
    server, port = await http_server(b"\x00\x01\x02 SSH-2.0-nothing like http\r\n\r\n")
    try:
        _, payload = await get(port)
    finally:
        server.close()
    assert payload["status"] == 0 and "not an HTTP response" in payload["error"]


async def test_a_server_that_drips_its_answer_is_cut_by_the_timeout():
    async def reply(writer):
        for byte in b"HTTP/1.1 200 OK\r\n" * 3:
            writer.write(bytes([byte]))
            await writer.drain()
            await asyncio.sleep(0.1)

    server, port = await http_server(reply)
    try:
        start = time.monotonic()
        _, payload = await get(port, limits=Limits(http_timeout=0.5, connect_timeout=1.0, rate_per_second=50.0))
        elapsed = time.monotonic() - start
    finally:
        server.close()
    assert payload == {"error": "timeout", "name": "example.com", "scheme": "http", "status": 0} and elapsed < 1.5


async def test_a_connection_that_closes_at_once_is_an_error_record():
    async def handle(reader, writer):
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        _, payload = await get(port)
    finally:
        server.close()
    assert payload["status"] == 0 and payload["error"]


@pytest.mark.parametrize("name", ["exa mple.com", "example.com\r\nX-Evil: 1", "ex@mple.com", "", "-bad.example.com", "a/b.example.com", "EXAMPLE.com"])
async def test_only_plain_host_names_go_into_a_request(name):
    seen = []
    server, port = await http_server(FULL, record=seen)
    try:
        with pytest.raises(ProbeRefused):
            await get(port, name=name)
        await asyncio.sleep(0.1)
    finally:
        server.close()
    assert seen == []


async def test_the_run_requests_each_name_on_open_web_ports_only(monkeypatch):
    seen = []
    server, port = await http_server(FULL, record=seen)
    monkeypatch.setattr(active, "HTTP_PORT", port)
    store, sid = make_active_store({"example.com": ["127.0.0.1"], "www.example.com": ["127.0.0.1"]}, ports={"127.0.0.1": [port]})
    try:
        await run_active(store, sid, load_packs(), config(max_connections=200))
    finally:
        server.close()
    http = [e for e in store.evidence_for_scan(sid) if e.source == "http"]
    assert sorted(json.loads(e.payload)["name"] for e in http) == ["example.com", "www.example.com"]
    assert sorted(re.search(r"Host: (\S+)", s).group(1) for s in seen) == ["example.com", "www.example.com"]
    assert all(f"User-Agent: {UA}" in s for s in seen)


def test_the_user_agent_is_generic_and_carries_no_address():
    assert active.USER_AGENT == UA and "@" not in UA and "http" not in UA.lower()
