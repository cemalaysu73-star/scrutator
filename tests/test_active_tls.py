"""Active confirmation, task 3: TLS posture (handshake only) against local TLS servers with throwaway certificates."""

import asyncio
import json
import ssl
import time
from datetime import datetime, timedelta

import pytest

from activefix import FAST, config, make_active_store
from scrutator import active
from scrutator.active import tlscheck
from scrutator.active.guard import Budget, Limits
from scrutator.active.net import ProbeRefused
from scrutator.active.run import run_active
from scrutator.packs import load_packs
from tlsfix import make_cert, tls_server

LOOP = frozenset({"loopback"})


async def handshake(port, sni="example.com", limits=FAST):
    ev = await tlscheck.tls_handshake("127.0.0.1", port, sni, limits=limits, budget=Budget(limits), relax=LOOP)
    return ev, json.loads(ev.payload)


async def test_a_valid_certificate_is_read_with_protocol_names_issuer_and_validity():
    server, port = await tls_server(make_cert("example.com", ["example.com", "www.example.com"], issuer_cn="Test CA"))
    try:
        ev, payload = await handshake(port)
    finally:
        server.close()
    assert ev.source == "tls" and ev.request == f"TLS HANDSHAKE 127.0.0.1:{port} sni=example.com"
    assert payload["handshake"] == "ok" and payload["protocol"] in ("TLSv1.3", "TLSv1.2") and payload["cipher"]
    assert payload["san"] == ["example.com", "www.example.com"] and payload["hostname_match"] is True
    assert payload["issuer"] == "CN=Test CA" and payload["subject"] == "CN=example.com" and payload["self_signed"] is False
    days = (datetime.fromisoformat(payload["not_after"]) - datetime.utcnow()).days
    assert 88 <= days <= 90


async def test_expired_expiring_and_mismatched_certificates_are_recorded_as_they_are():
    for cert, key, expected in (
        (make_cert(not_before_days=-400, not_after_days=-5), "not_after", lambda p: datetime.fromisoformat(p["not_after"]) < datetime.utcnow()),
        (make_cert(not_after_days=10), "not_after", lambda p: 8 <= (datetime.fromisoformat(p["not_after"]) - datetime.utcnow()).days <= 10),
        (make_cert("other.example.org", ["other.example.org"]), "hostname_match", lambda p: p["hostname_match"] is False),
    ):
        server, port = await tls_server(cert)
        try:
            _, payload = await handshake(port)
        finally:
            server.close()
        assert payload["handshake"] == "ok" and expected(payload), (key, payload)


@pytest.mark.parametrize("name,patterns,expected", [
    ("example.com", ["example.com"], True), ("WWW.Example.COM.", ["www.example.com"], True),
    ("www.example.com", ["*.example.com"], True), ("a.b.example.com", ["*.example.com"], False),
    ("example.com", ["*.example.com"], False), ("evilexample.com", ["*.example.com"], False),
    ("www.example.com", ["*.*.com"], False), ("www.example.com", [], False),
])
def test_hostname_matching_follows_the_wildcard_rule(name, patterns, expected):
    assert tlscheck.hostname_matches(name, patterns) is expected


async def test_a_certificate_without_san_falls_back_to_the_common_name():
    server, port = await tls_server(make_cert("example.com", ()))
    try:
        _, payload = await handshake(port)
    finally:
        server.close()
    assert payload["san"] == [] and payload["hostname_match"] is True


async def test_hostile_certificate_text_is_cleaned():
    cert = make_cert("evil\x1b[31m‮example.com", ["example.com"])
    server, port = await tls_server(cert)
    try:
        _, payload = await handshake(port)
    finally:
        server.close()
    assert "\x1b" not in payload["subject"] and "‮" not in payload["subject"]


async def test_a_port_that_does_not_speak_tls_is_a_failed_handshake_not_a_crash():
    async def handle(reader, writer):
        writer.write(b"SSH-2.0-OpenSSH_9.6\r\n")
        await writer.drain()
        await asyncio.sleep(0.3)
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        _, payload = await handshake(port)
    finally:
        server.close()
    assert payload["handshake"] == "failed" and payload["detail"] and "protocol" not in payload


async def test_a_server_that_stalls_the_handshake_is_cut_by_the_timeout():
    async def handle(reader, writer):
        await asyncio.sleep(10)

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        start = time.monotonic()
        _, payload = await handshake(port, limits=Limits(handshake_timeout=0.5, connect_timeout=1.0, rate_per_second=50.0))
        elapsed = time.monotonic() - start
    finally:
        server.close()
    assert payload == {"detail": "timeout", "handshake": "failed", "sni": "example.com"} and elapsed < 2.0


async def test_the_handshake_respects_the_guards():
    seen = []
    server, port = await tls_server(make_cert(), on_connect=lambda: seen.append(1))
    try:
        with pytest.raises(ProbeRefused):
            await tlscheck.tls_handshake("127.0.0.1", port, "example.com", limits=FAST, budget=Budget(FAST))  # loopback, not relaxed
        spent = Budget(Limits(max_connections=1, rate_per_second=50.0))
        await spent.take()
        assert await tlscheck.tls_handshake("127.0.0.1", port, "example.com", limits=FAST, budget=spent, relax=LOOP) is None
        await asyncio.sleep(0.1)
    finally:
        server.close()
    assert seen == []


# ------------------------------------------------------------------------------------------------ legacy protocols


async def test_the_machine_says_whether_it_can_offer_the_old_protocols():
    for version in tlscheck.LEGACY:
        assert isinstance(await tlscheck.can_offer(version), bool)


async def legacy(port, version):
    ev = await tlscheck.legacy_probe("127.0.0.1", port, version, "example.com", limits=FAST, budget=Budget(FAST), relax=LOOP)
    return ev, json.loads(ev.payload)


@pytest.mark.parametrize("version,floor", [("TLSv1", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)])
async def test_a_server_that_still_accepts_the_old_protocol_is_reported_as_accepting_it(version, floor):
    if not await tlscheck.can_offer(version):
        pytest.skip(f"this platform's TLS library cannot offer {version}, so it cannot be served or tested here")
    server, port = await tls_server(make_cert(), low=floor, high=floor)
    try:
        ev, payload = await legacy(port, version)
    finally:
        server.close()
    assert ev.request == f"TLS LEGACY 127.0.0.1:{port} {version}" and payload["result"] == "accepted"


@pytest.mark.parametrize("version", ["TLSv1", "TLSv1.1"])
async def test_a_modern_only_server_refuses_the_old_protocols(version):
    if not await tlscheck.can_offer(version):
        pytest.skip(f"this platform's TLS library cannot offer {version}")
    server, port = await tls_server(make_cert(), low=ssl.TLSVersion.TLSv1_2)
    try:
        _, payload = await legacy(port, version)
    finally:
        server.close()
    assert payload["result"] == "refused"


async def test_when_the_machine_cannot_offer_the_protocol_nothing_is_concluded_and_nothing_is_sent(monkeypatch):
    seen = []
    server, port = await tls_server(make_cert(), on_connect=lambda: seen.append(1))
    monkeypatch.setattr(tlscheck, "_SELF_TEST", {"TLSv1": False, "TLSv1.1": False})
    try:
        _, payload = await legacy(port, "TLSv1")
        await asyncio.sleep(0.1)
    finally:
        server.close()
    assert payload["result"] == "unsupported" and "nothing is concluded" in payload["detail"] and seen == []


# ------------------------------------------------------------------------------------------------ the run


async def test_the_run_handshakes_open_tls_ports_per_name_and_tries_the_legacy_protocols(monkeypatch):
    server, port = await tls_server(make_cert("example.com", ["example.com", "www.example.com"]))
    monkeypatch.setattr(active, "TLS_PORTS", (port,))
    monkeypatch.setattr(active, "HTTPS_PORT", port)
    store, sid = make_active_store({"example.com": ["127.0.0.1"], "www.example.com": ["127.0.0.1"], "mail.example.com": ["127.0.0.1"]}, ports={"127.0.0.1": [port]})
    try:
        summary = await run_active(store, sid, load_packs(), config(max_connections=200))
    finally:
        server.close()
    tls = [e for e in store.evidence_for_scan(sid) if e.source == "tls"]
    handshakes = {json.loads(e.payload)["sni"]: json.loads(e.payload) for e in tls if "HANDSHAKE" in e.request}
    # a name the certificate does not cover is found out, not assumed
    assert set(handshakes) == {"example.com", "mail.example.com", "www.example.com"} and handshakes["mail.example.com"]["hostname_match"] is False
    assert handshakes["www.example.com"]["hostname_match"] is True
    assert sorted(e.request.rsplit(" ", 1)[1] for e in tls if "LEGACY" in e.request) == ["TLSv1", "TLSv1.1"]
    log = store.audit_log(sid)
    assert len([r for r in log if r.get("module") == "tls" and r["event"] == "ok"]) == len(tls)
    assert summary["connections"] <= 200 and store.verify_audit(sid)
