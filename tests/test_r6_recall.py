"""R6 task 2: recall that does not depend on a lucky quota day.

- the crt.sh module falls back to crt.sh's public database when the web search fails, with the same row shape and a
  fixed query (and never SQL from a bundle); the pgwire client refuses anything but a trust session;
- mined mentions: in-scope names written inside evidence the scan already holds become `mentions` relations, in scope
  only, citing the record that contains them; no new request;
- the THC aggregator reads its CSV and reports quota as unavailable;
- opt-in `--axfr` needs `--active`, records the authorisation, and every outcome (zone, refusal, timeout) is evidence;
- a name only a zone transfer lists is verified (authoritative) even without an address.
"""

import asyncio
import json
import struct

import httpx
import pytest
import respx

from scrutator.model import Entity, EntityType, Evidence, ScopeState
from scrutator.modules.base import Fact, Module, ModuleContext, Observation, SourceUnavailable
from scrutator.scope import ScopePolicy
from scrutator.store import Store
from tests.conftest import FakeResolver

D, IP = EntityType.DOMAIN, EntityType.IP


def dom(v):
    return Entity(type=D, value=v)


def ip(v):
    return Entity(type=IP, value=v)


# ------------------------------------------------------------------------------------------ crt.sh database fallback


from scrutator.modules import crtsh
from scrutator.modules.crtsh import CrtSh, DB_HOST, db_query, db_request, db_rows


def test_the_query_is_fixed_and_refuses_a_name_that_is_not_a_host():
    sql = db_query("example.com")
    assert "plainto_tsquery('certwatch', 'example.com')" in sql and "LIKE '%.example.com'" in sql
    for bad in ("example.com'; DROP TABLE ca;--", "a b", "x';--"):
        with pytest.raises(Exception):
            db_query(bad)


def test_the_database_rows_take_the_web_search_shape():
    rows = db_rows(["id", "issuer_name", "name_value", "not_before", "not_after"],
                   [["12", "C=US, O=Let's Encrypt", "example.com\nwww.example.com", "2026-01-01 00:00:00", "2026-04-01 00:00:00"]])
    assert rows == [{"id": 12, "issuer_name": "C=US, O=Let's Encrypt", "name_value": "example.com\nwww.example.com",
                     "not_before": "2026-01-01T00:00:00", "not_after": "2026-04-01T00:00:00"}]


async def test_the_web_search_is_used_when_it_answers_and_the_database_is_not_touched(make_ctx, monkeypatch):
    monkeypatch.setattr(crtsh, "DB_FALLBACK", True)
    called = []
    monkeypatch.setattr(crtsh.pgwire, "query", lambda *a, **k: called.append(a))
    with respx.mock() as router:
        router.get("https://crt.sh/").mock(return_value=httpx.Response(200, json=[{"id": 1, "issuer_name": "x", "name_value": "example.com\nwww.example.com", "not_before": "2026-01-01T00:00:00", "not_after": "2026-04-01T00:00:00"}]))
        obs = await CrtSh().run(dom("example.com"), make_ctx())
    assert {o.entity.value for o in obs} == {"www.example.com"} and not called
    assert obs[0].evidence.request.startswith("GET https://crt.sh/")


async def test_the_database_answers_when_the_web_search_fails(make_ctx, monkeypatch):
    monkeypatch.setattr(crtsh, "DB_FALLBACK", True)

    async def fake_query(host, sql, **kw):
        assert host == DB_HOST and "plainto_tsquery" in sql
        return (["id", "issuer_name", "name_value", "not_before", "not_after"],
                [["7", "C=US, O=Let's Encrypt", "example.com\napi.example.com", "2026-01-01 00:00:00", "2026-04-01 00:00:00"]])

    monkeypatch.setattr(crtsh.pgwire, "query", fake_query)
    with respx.mock() as router:
        router.get("https://crt.sh/").mock(return_value=httpx.Response(502))
        obs = await CrtSh().run(dom("example.com"), make_ctx())
    assert {o.entity.value for o in obs} == {"api.example.com"}
    assert obs[0].evidence.request == db_request("example.com") == "PGSQL crt.sh:5432/certwatch identities example.com"
    assert json.loads(obs[0].evidence.payload)[0]["not_after"] == "2026-04-01T00:00:00"


async def test_both_failing_is_one_source_failure(make_ctx, monkeypatch):
    monkeypatch.setattr(crtsh, "DB_FALLBACK", True)

    async def boom(*a, **k):
        raise ConnectionError("no route")

    monkeypatch.setattr(crtsh.pgwire, "query", boom)
    with respx.mock() as router:
        router.get("https://crt.sh/").mock(return_value=httpx.Response(502))
        with pytest.raises(SourceUnavailable):
            await CrtSh().run(dom("example.com"), make_ctx())


async def test_the_fallback_is_off_in_tests_by_default(make_ctx):
    assert crtsh.DB_FALLBACK is False  # conftest turns it off; no test opens a connection to crt.sh
    with respx.mock() as router:
        router.get("https://crt.sh/").mock(return_value=httpx.Response(502))
        with pytest.raises(Exception):
            await CrtSh().run(dom("example.com"), make_ctx())


# ------------------------------------------------------------------------------------------ pgwire client


from scrutator import pgwire


async def _serve(handler):
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        yield port


def _msg(kind, body=b""):
    return kind + struct.pack("!I", len(body) + 4) + body


async def test_pgwire_runs_a_simple_query_against_a_trust_server():
    async def handler(reader, writer):
        await reader.readexactly(4)  # length of startup
        length = struct.unpack("!I", await reader.readexactly(4))[0] if False else None
        # read the rest of the startup packet by draining what is buffered
        await asyncio.sleep(0)
        try:
            await asyncio.wait_for(reader.read(4096), 0.1)
        except asyncio.TimeoutError:
            pass
        writer.write(_msg(b"R", struct.pack("!I", 0)))  # AuthenticationOk
        writer.write(_msg(b"Z", b"I"))
        await reader.readexactly(1)  # 'Q'
        qlen = struct.unpack("!I", await reader.readexactly(4))[0]
        await reader.readexactly(qlen - 4)
        row_desc = struct.pack("!H", 1) + b"name_value\0" + struct.pack("!IHIHIH", 0, 0, 25, 0xFFFF, 0xFFFFFFFF, 0)
        writer.write(_msg(b"T", row_desc))
        val = b"example.com"
        writer.write(_msg(b"D", struct.pack("!H", 1) + struct.pack("!i", len(val)) + val))
        writer.write(_msg(b"C", b"SELECT 1\0"))
        writer.write(_msg(b"Z", b"I"))
        await writer.drain()
        try:
            await reader.readexactly(5)  # terminate
        except Exception:
            pass
        writer.close()

    gen = _serve(handler)
    port = await gen.__anext__()
    try:
        columns, rows = await pgwire.query("127.0.0.1", "SELECT name_value FROM x", port=port, timeout=5)
        assert columns == ["name_value"] and rows == [["example.com"]]
    finally:
        await gen.aclose()


async def test_pgwire_refuses_a_server_that_asks_for_a_password():
    async def handler(reader, writer):
        try:
            await asyncio.wait_for(reader.read(4096), 0.1)
        except asyncio.TimeoutError:
            pass
        writer.write(_msg(b"R", struct.pack("!I", 3)))  # AuthenticationCleartextPassword
        await writer.drain()
        try:
            await reader.readexactly(5)
        except Exception:
            pass
        writer.close()

    gen = _serve(handler)
    port = await gen.__anext__()
    try:
        with pytest.raises(pgwire.PgError, match="password"):
            await pgwire.query("127.0.0.1", "SELECT 1", port=port, timeout=5)
    finally:
        await gen.aclose()


# ------------------------------------------------------------------------------------------ mined mentions


from scrutator.engine import Engine
from scrutator import mentions


def test_the_name_miner_finds_in_scope_names_and_rejects_look_alikes():
    assert mentions.mentioned("redirect to https://login.example.com/next", {"example.com"}) == ["login.example.com"]
    assert mentions.mentioned("example.com.evil.net and a.example.com.evil.net", {"example.com"}) == []
    assert mentions.mentioned("ns1.example.com. serves it", {"example.com"}) == ["ns1.example.com"]
    assert mentions.mentioned("%2Fwww.example.com", {"example.com"}) == ["www.example.com"]


class Lister(Module):
    name = "wayback"
    name_weight = 2
    accepts = frozenset({D})
    apex_only = True

    async def run(self, entity, ctx):
        # the field the module reads names one host; the payload (an archived URL) mentions two more in scope
        ev = Evidence.create("wayback", f"GET https://web.archive.org/x?q={entity.value}", json.dumps([
            "https://www.example.com/a?next=https://login.example.com/",
            "https://cdn.example.com/x",
        ]))
        return [Observation(dom("www.example.com"), "has_subdomain", ev)]


async def test_evidence_payloads_are_mined_for_in_scope_names_without_a_request():
    store = Store(":memory:")
    engine = Engine(store, ScopePolicy(domains=["example.com"]), ctx=None)
    scan = store.create_scan("example.com")
    store.upsert_entity(scan, dom("example.com"), ScopeState.IN)
    found = await engine.run_module(scan, Lister(), dom("example.com"))
    values = {e.value for e in found}
    assert {"www.example.com", "login.example.com", "cdn.example.com"} <= values
    edges = {(e.rel, e.dst) for e in store.edges(scan)}
    assert ("mentions", "domain:login.example.com") in edges and ("mentions", "domain:cdn.example.com") in edges
    # each mention cites the record that contains it
    mined = [e for e in store.edges(scan) if e.rel == "mentions" and e.dst == "domain:login.example.com"][0]
    assert "login.example.com" in store.get_evidence(mined.evidence_ids[0]).payload


async def test_mining_can_be_turned_off_and_never_leaves_the_scope():
    store = Store(":memory:")
    engine = Engine(store, ScopePolicy(domains=["example.com"]), ctx=None, mine_mentions=False)
    scan = store.create_scan("example.com")
    store.upsert_entity(scan, dom("example.com"), ScopeState.IN)
    found = await engine.run_module(scan, Lister(), dom("example.com"))
    assert not any(e.rel == "mentions" for e in store.edges(scan))


class OutLister(Module):
    name = "wayback"
    accepts = frozenset({D})
    apex_only = True

    async def run(self, entity, ctx):
        ev = Evidence.create("wayback", "GET https://web.archive.org/x", json.dumps(["https://out.evil.net/ and foo.example.com"]))
        return [Observation(dom("www.example.com"), "has_subdomain", ev)]


async def test_an_out_of_scope_name_in_a_payload_is_not_mined():
    store = Store(":memory:")
    engine = Engine(store, ScopePolicy(domains=["example.com"]), ctx=None)
    scan = store.create_scan("example.com")
    store.upsert_entity(scan, dom("example.com"), ScopeState.IN)
    await engine.run_module(scan, OutLister(), dom("example.com"))
    mentioned = {e.dst for e in store.edges(scan) if e.rel == "mentions"}
    assert "domain:foo.example.com" in mentioned and not any("evil.net" in m for m in mentioned)


# ------------------------------------------------------------------------------------------ THC aggregator


from scrutator.modules.thc import Thc


async def test_thc_reads_its_csv_and_drops_the_header(make_ctx):
    body = "subdomain\nwww.example.com\napi.example.com\nout.other.net\n"
    with respx.mock() as router:
        router.get("https://ip.thc.org/api/v1/subdomains/download").mock(return_value=httpx.Response(200, text=body))
        obs = await Thc().run(dom("example.com"), make_ctx())
    assert {o.entity.value for o in obs} == {"www.example.com", "api.example.com"}
    assert obs[0].evidence.source == "thc"


async def test_thc_reports_its_rate_limit_as_unavailable(make_ctx):
    with respx.mock() as router:
        router.get("https://ip.thc.org/api/v1/subdomains/download").mock(return_value=httpx.Response(429))
        with pytest.raises(SourceUnavailable):
            await Thc().run(dom("example.com"), make_ctx())


# ------------------------------------------------------------------------------------------ AXFR


from scrutator.modules import axfr as axfr_mod
from scrutator.modules.axfr import Axfr, names_in


def test_names_in_keeps_owners_and_in_scope_targets_only():
    lines = [
        "www.zonetransfer.me. 7200 IN A 1.2.3.4",
        "staging.zonetransfer.me. 7200 IN CNAME www.sydneyoperahouse.com.",
        "_sip._tcp.zonetransfer.me. 14000 IN SRV 0 0 5060 www.zonetransfer.me.",
    ]
    # owners (every left-hand name) and the in-scope SRV target; the out-of-scope CNAME target is dropped
    assert names_in(lines, "zonetransfer.me") == ["_sip._tcp.zonetransfer.me", "staging.zonetransfer.me", "www.zonetransfer.me"]


def _axfr_server(zone_name, extra_rrsets):
    """A one-shot TCP AXFR responder on localhost, so the real socket-and-parse path runs (not a stub)."""
    import socket as socketlib
    import struct as structlib
    import threading

    import dns.flags
    import dns.message
    import dns.rrset

    sock = socketlib.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]

    def serve():
        conn, _ = sock.accept()
        try:
            length = structlib.unpack("!H", conn.recv(2))[0]
            query = dns.message.from_wire(conn.recv(length))
            soa = dns.rrset.from_text(zone_name, 300, "IN", "SOA", f"ns.{zone_name} a.{zone_name} 1 2 3 4 5")
            response = dns.message.make_response(query)
            response.flags |= dns.flags.AA
            response.answer = [soa, *extra_rrsets, soa]
            wire = response.to_wire()
            conn.sendall(structlib.pack("!H", len(wire)) + wire)
        finally:
            conn.close()
            sock.close()

    threading.Thread(target=serve, daemon=True).start()
    return port


async def test_axfr_records_the_zone_and_turns_owners_into_names(monkeypatch):
    import dns.rrset

    port = _axfr_server("zonetransfer.me.", [
        dns.rrset.from_text("www.zonetransfer.me.", 7200, "IN", "A", "217.147.180.162"),
        dns.rrset.from_text("vpn.zonetransfer.me.", 4000, "IN", "A", "174.36.59.154"),
    ])
    monkeypatch.setattr(axfr_mod, "XFR_PORT", port)
    resolver = FakeResolver({("zonetransfer.me", "NS"): ["nsztm1.digi.ninja."], ("nsztm1.digi.ninja", "A"): ["127.0.0.1"]})
    out = await Axfr().run(dom("zonetransfer.me"), ModuleContext(http=None, resolver=resolver))
    names = {o.entity.value for o in out if isinstance(o, Observation)}
    assert {"www.zonetransfer.me", "vpn.zonetransfer.me"} <= names
    record = [o for o in out if isinstance(o, Observation)][0].evidence
    assert "vpn.zonetransfer.me" in record.payload and record.request.startswith("AXFR zonetransfer.me @nsztm1.digi.ninja")


async def test_a_refused_transfer_is_recorded_as_a_fact(monkeypatch):
    import dns.xfr

    def refuse(address, z, port, timeout):
        raise dns.xfr.TransferError(5)

    monkeypatch.setattr(axfr_mod, "_transfer", refuse)
    resolver = FakeResolver({("example.com", "NS"): ["a.iana-servers.net."], ("a.iana-servers.net", "A"): ["199.43.135.53"]})
    out = await Axfr().run(dom("example.com"), ModuleContext(http=None, resolver=resolver))
    assert len(out) == 1 and isinstance(out[0], Fact) and "REFUSED" in out[0].evidence.payload


async def test_axfr_is_active_and_opt_in():
    assert Axfr.mode.value == "active" and Axfr.opt_in and Axfr.replayable is False


def test_a_name_only_a_zone_transfer_lists_is_verified_without_an_address():
    from scrutator.names import name_states

    report = {
        "scope": {"domains": ["zonetransfer.me"], "cidrs": [], "asns": []},
        "entities": [
            {"id": "domain:zonetransfer.me", "type": "domain", "value": "zonetransfer.me", "state": "in"},
            {"id": "domain:vpn.zonetransfer.me", "type": "domain", "value": "vpn.zonetransfer.me", "state": "in"},
        ],
        "edges": [{"src": "domain:zonetransfer.me", "rel": "has_subdomain", "dst": "domain:vpn.zonetransfer.me", "evidence_ids": ["e1"]}],
        "evidence": {"e1": {"source": "axfr", "request": "AXFR zonetransfer.me @ns", "payload": "vpn.zonetransfer.me. 4000 IN A 174.36.59.154", "collected_at": "2026-10-21T00:00:00+00:00"}},
    }
    rows = {r["name"]: r for r in name_states(report)}
    assert rows["vpn.zonetransfer.me"]["tier"] == "verified" and rows["vpn.zonetransfer.me"]["basis"] == "zone"


async def test_axfr_without_an_address_for_the_name_server_is_recorded():
    resolver = FakeResolver({("example.com", "NS"): ["dead.ns.example."]})
    out = await Axfr().run(dom("example.com"), ModuleContext(http=None, resolver=resolver))
    assert len(out) == 1 and isinstance(out[0], Fact) and "NO ADDRESS" in out[0].evidence.payload
