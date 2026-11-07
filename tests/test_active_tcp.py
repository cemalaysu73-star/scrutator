"""Active confirmation, task 2: TCP connect check and read-only banner capture, against local listeners on 127.0.0.1."""

import asyncio
import json
import socket
import time

import pytest

from activefix import FAST, RELAX, config, make_active_store
from scrutator import proxy
from scrutator.active.guard import Budget, Limits
from scrutator.active.net import ProbeRefused
from scrutator.active.run import run_active
from scrutator.active.tcpcheck import banner_text, classify, tcp_check
from scrutator.packs import load_packs

LOOP = frozenset({"loopback"})


async def serve(handler):
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def check(port, limits=FAST, relax=LOOP):
    ev = await tcp_check("127.0.0.1", port, limits=limits, budget=Budget(limits), relax=relax)
    return ev, json.loads(ev.payload)


async def test_open_port_with_a_banner_is_open_and_the_banner_is_recorded():
    async def handle(reader, writer):
        writer.write(b"SSH-2.0-OpenSSH_9.6 Ubuntu\r\n")
        await writer.drain()
        await asyncio.sleep(0.2)
        writer.close()

    server, port = await serve(handle)
    try:
        ev, payload = await check(port)
    finally:
        server.close()
    assert ev.source == "tcp" and ev.request == f"TCP CONNECT 127.0.0.1:{port}"
    assert payload == {"banner": "SSH-2.0-OpenSSH_9.6 Ubuntu", "banner_bytes": 28, "state": "open"}


async def test_nothing_is_ever_sent_to_an_open_port():
    received = []

    async def handle(reader, writer):
        try:
            received.append(await asyncio.wait_for(reader.read(100), 0.6))
        except asyncio.TimeoutError:
            received.append(b"<silence>")
        writer.close()

    server, port = await serve(handle)
    try:
        _, payload = await check(port)
        await asyncio.sleep(0.8)
    finally:
        server.close()
    assert payload["state"] == "open" and payload["banner"] == ""
    assert received in ([b""], [b"<silence>"])  # EOF or silence: not one byte arrived from the probe


async def test_a_closed_port_is_closed_and_costs_one_connection():
    limits = Limits(max_connections=5, connect_timeout=4.0, rate_per_second=50.0)  # Windows retries a refused connect for about 2 s
    budget = Budget(limits)
    ev = await tcp_check("127.0.0.1", free_port(), limits=limits, budget=budget, relax=LOOP)
    assert json.loads(ev.payload)["state"] == "closed" and budget.used == 1


async def test_a_silent_proxy_shows_as_filtered_after_the_timeout():
    async def silent(reader, writer):
        await asyncio.sleep(5)

    server, pport = await serve(silent)
    proxy.set_proxy(f"http://127.0.0.1:{pport}")
    try:
        start = time.monotonic()
        _, payload = await check(80, Limits(connect_timeout=0.6, rate_per_second=50.0))
        elapsed = time.monotonic() - start
    finally:
        proxy.set_proxy(None)
        server.close()
    assert payload["state"] == "filtered" and "no answer within 0.6 s" in payload["detail"] and 0.5 < elapsed < 2.0


@pytest.mark.parametrize("exc,state", [
    (asyncio.TimeoutError(), "filtered"), (ConnectionRefusedError(), "closed"), (ConnectionResetError(), "closed"),
    (OSError(113, "No route to host"), "filtered"), (proxy.TunnelError("refused", "x"), "closed"),
    (proxy.TunnelError("timeout", "x"), "filtered"), (proxy.TunnelError("proxy", "denied"), "error"),
])
def test_failures_are_classified(exc, state):
    assert classify(exc, FAST)[0] == state


async def test_a_refused_address_is_never_connected_to_even_if_a_caller_asks():
    seen = []

    async def handle(reader, writer):
        seen.append(1)
        writer.close()

    server, port = await serve(handle)
    try:
        with pytest.raises(ProbeRefused, match="loopback"):
            await tcp_check("127.0.0.1", port, limits=FAST, budget=Budget(FAST), relax=frozenset())
        with pytest.raises(ProbeRefused):
            await tcp_check("10.1.2.3", 80, limits=FAST, budget=Budget(FAST))
        with pytest.raises(ProbeRefused, match="not a port"):
            await tcp_check("127.0.0.1", 70000, limits=FAST, budget=Budget(FAST), relax=LOOP)
        await asyncio.sleep(0.1)
    finally:
        server.close()
    assert seen == []


# ------------------------------------------------------------------------------------------------ hostile banners


HOSTILE = [
    (b"\x1b[31mRED\x1b[0m login:\r\n", "RED login:"),
    (b"\x1b]0;pwned\x07title-set\r\n", "title-set"),
    (b"\x1b[2J\x1b[Hcleared\r\n", "cleared"),
    (b"ok\x00\x01\x02\x07bell\r\n", "okbell"),
    (b"\xe2\x80\xaegnp.exe\r\n", "gnp.exe"),  # a right-to-left override
    (b"\xff\xfd\x18\xff\xfd\x20Welcome to the router\r\n", "Welcome to the router"),  # Telnet IAC negotiation, then text
    (b"line1\nline2\ttabbed\r\n\r\n", "line1 line2 tabbed"),
]


@pytest.mark.parametrize("raw,expected", HOSTILE)
async def test_hostile_banners_are_sanitised(raw, expected):
    async def handle(reader, writer):
        writer.write(raw)
        await writer.drain()
        writer.close()

    server, port = await serve(handle)
    try:
        _, payload = await check(port)
    finally:
        server.close()
    assert payload["banner"] == expected
    assert not any(ord(c) < 32 or 0x7F <= ord(c) <= 0x9F or c in "‮⁦" for c in payload["banner"])


def test_telnet_negotiation_alone_is_noted_not_shown():
    assert banner_text(b"\xff\xfd\x18\xff\xfb\x01") == ("", "telnet option negotiation, no text")
    assert banner_text(b"\x80\x81\x82")[1] == "binary data, no text" or banner_text(b"\x80\x81\x82")[0]


async def test_an_endless_banner_is_cut_at_256_bytes_and_the_probe_closes():
    async def handle(reader, writer):
        try:
            for _ in range(2000):
                writer.write(b"A" * 1000)
                await writer.drain()
        except ConnectionError:
            pass
        writer.close()

    server, port = await serve(handle)
    try:
        start = time.monotonic()
        _, payload = await check(port, Limits(banner_timeout=1.0, connect_timeout=1.0, rate_per_second=50.0))
        elapsed = time.monotonic() - start
    finally:
        server.close()
    assert payload["banner_bytes"] == 256 and len(payload["banner"]) <= 256 and elapsed < 1.5


async def test_a_dripping_banner_is_cut_by_the_clock():
    async def handle(reader, writer):
        try:
            for _ in range(100):
                writer.write(b"x")
                await writer.drain()
                await asyncio.sleep(0.05)
        except ConnectionError:
            pass
        writer.close()

    server, port = await serve(handle)
    try:
        start = time.monotonic()
        _, payload = await check(port, Limits(banner_timeout=0.4, connect_timeout=1.0, rate_per_second=50.0))
        elapsed = time.monotonic() - start
    finally:
        server.close()
    assert payload["state"] == "open" and 0 < payload["banner_bytes"] < 20 and elapsed < 1.2


# ------------------------------------------------------------------------------------------------ the run


async def _until_closed(reader):
    while await reader.read(100):
        pass


async def listeners(count, *, hold=0.0, state=None):
    state = state if state is not None else {"now": 0, "peak": 0, "total": 0}

    async def handle(reader, writer):
        state["now"] += 1
        state["total"] += 1
        state["peak"] = max(state["peak"], state["now"])
        try:
            await asyncio.wait_for(_until_closed(reader), hold)  # held until the probe closes (or `hold` passes)
        except asyncio.TimeoutError:
            pass
        finally:
            state["now"] -= 1
            writer.close()

    servers, ports = [], []
    for _ in range(count):
        server, port = await serve(handle)
        servers.append(server)
        ports.append(port)
    return servers, ports, state


def evidence_of(store, sid, source="tcp"):
    return [e for e in store.evidence_for_scan(sid) if e.source == source]


async def test_the_run_probes_every_planned_port_and_records_evidence_and_audit_per_probe():
    servers, ports, state = await listeners(3)
    store, sid = make_active_store({"example.com": ["127.0.0.1"]}, ports={"127.0.0.1": ports})
    try:
        summary = await run_active(store, sid, load_packs(), config(max_connections=100))
    finally:
        for s in servers:
            s.close()
    evidence = evidence_of(store, sid)
    open_ports = sorted(int(e.request.rsplit(":", 1)[1]) for e in evidence if json.loads(e.payload)["state"] == "open")
    assert set(ports) <= set(open_ports) and summary["tcp"]["open"] == len(open_ports)  # (this machine may listen on 445 itself)
    assert len(evidence) == 3 + 18 + 2  # passive ports, the fixed risky list and 80/443 (none of those listens here)
    log = store.audit_log(sid)
    assert len([r for r in log if r.get("module") == "tcp" and r["event"] == "ok"]) == len(evidence)
    assert store.verify_audit(sid) and all(e.collected_at for e in evidence)


async def test_concurrency_never_exceeds_the_limit():
    servers, ports, state = await listeners(10, hold=0.4)
    store, sid = make_active_store({"example.com": ["127.0.0.1"]}, ports={"127.0.0.1": ports})
    try:
        await run_active(store, sid, load_packs(), config(max_connections=200, concurrency=3, banner_timeout=0.35))
    finally:
        for s in servers:
            s.close()
    assert state["total"] == 10 and 2 <= state["peak"] <= 3


async def test_the_rate_limit_spaces_connections():
    servers, ports, state = await listeners(2)
    store, sid = make_active_store({"example.com": ["127.0.0.1"]}, ports={"127.0.0.1": ports})
    try:
        start = time.monotonic()
        summary = await run_active(store, sid, load_packs(), config(max_connections=12, tcp_share=1.0, rate_per_second=10.0))
        elapsed = time.monotonic() - start
    finally:
        for s in servers:
            s.close()
    assert summary["connections"] == 12 and elapsed >= 11 / 10 * 0.8  # twelve connections at ten a second take about 1.1 s


async def test_the_connection_cap_is_hard():
    servers, ports, state = await listeners(6)
    store, sid = make_active_store({"example.com": ["127.0.0.1"]}, ports={"127.0.0.1": ports})
    try:
        summary = await run_active(store, sid, load_packs(), config(max_connections=5, tcp_share=1.0))
    finally:
        for s in servers:
            s.close()
    assert summary["connections"] <= 5 and state["total"] <= 5
    assert len(evidence_of(store, sid)) <= 5


async def test_the_deadline_ends_the_run_and_says_so():
    servers, ports, state = await listeners(8, hold=1.0)
    store, sid = make_active_store({"example.com": ["127.0.0.1"]}, ports={"127.0.0.1": ports})
    try:
        start = time.monotonic()
        summary = await run_active(store, sid, load_packs(), config(max_connections=200, concurrency=2, banner_timeout=1.0, deadline_s=0.8))
        elapsed = time.monotonic() - start
    finally:
        for s in servers:
            s.close()
    assert summary["stopped"] == "deadline" and elapsed < 3.0
    assert store.audit_log(sid)[-1]["event"] == "active_done" and store.audit_log(sid)[-1]["stopped"] == "deadline"


async def test_ctrl_c_stops_the_probes_keeps_the_evidence_and_leaves_a_consistent_log():
    servers, ports, state = await listeners(6, hold=2.0)
    store, sid = make_active_store({"example.com": ["127.0.0.1"]}, ports={"127.0.0.1": ports})
    task = asyncio.ensure_future(run_active(store, sid, load_packs(), config(max_connections=200, concurrency=2, banner_timeout=2.0, deadline_s=20)))
    await asyncio.sleep(0.9)
    task.cancel()
    start = time.monotonic()
    with pytest.raises(asyncio.CancelledError):
        await task
    for s in servers:
        s.close()
    assert time.monotonic() - start < 1.0
    log = store.audit_log(sid)
    assert log[-1]["event"] == "active_interrupted" and store.verify_audit(sid)
    assert json.loads(store.get_meta(sid, "active"))["interrupted"] is True
    await asyncio.sleep(0.1)
    assert len(evidence_of(store, sid)) < 26  # not every planned probe had finished


async def test_a_proxy_failure_is_recorded_as_an_error_state_not_as_a_closed_port():
    async def deny(reader, writer):
        await reader.read(1024)
        writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
        await writer.drain()
        writer.close()

    server, pport = await serve(deny)
    proxy.set_proxy(f"http://127.0.0.1:{pport}")
    store, sid = make_active_store({"example.com": ["127.0.0.1"]})
    try:
        await run_active(store, sid, load_packs(), config(max_connections=30))
    finally:
        proxy.set_proxy(None)
        server.close()
    states = {json.loads(e.payload)["state"] for e in evidence_of(store, sid)}
    assert states == {"error"}
