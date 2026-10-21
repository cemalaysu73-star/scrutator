"""R6 bench section `recall_speed`: the round's new mechanisms on offline fixtures.

- mined mentions: a lookup whose payload names in-scope hosts it does not report itself; every one is found, none
  outside the scope, and no request is made for it;
- zone transfer: a local AXFR responder on the loopback interface serves a planted zone; `--axfr` turns every name in
  it into a verified name, and a refusing server is recorded as evidence, not silence;
- live names: the names printed while a scan runs are exactly the names the report calls live (and therefore verified).

Fixtures written by the author of the code they test: they measure the mechanisms, not real-world coverage.
"""

from __future__ import annotations

import asyncio
import json
import socket
import struct
import threading

import dns.flags
import dns.message
import dns.rrset

from scrutator.engine import Engine
from scrutator.livenames import LiveNames
from scrutator.model import Entity, EntityType, Evidence, ScopeState
from scrutator.modules import axfr as axfr_module
from scrutator.modules.base import Fact, Module, ModuleContext, Observation
from scrutator.names import name_states
from scrutator.resolver import DnsAnswer
from scrutator.scope import ScopePolicy
from scrutator.store import Store

D = EntityType.DOMAIN
ZONE = "lab.example."
PLANTED = ["vpn.lab.example", "owa.lab.example", "_sip._tcp.lab.example", "dc-office.lab.example", "intns1.lab.example"]


def dom(value: str) -> Entity:
    return Entity(type=D, value=value)


class _StaticResolver:
    def __init__(self, records: dict):
        self.records = records

    async def lookup(self, name, rtype):
        return list(self.records.get((name, rtype), []))


def _serve_once(rrsets: list | None, refuse: bool = False) -> int:
    """A one-shot AXFR responder on 127.0.0.1; returns its port."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]

    def serve():
        conn, _ = sock.accept()
        try:
            length = struct.unpack("!H", conn.recv(2))[0]
            query = dns.message.from_wire(conn.recv(length))
            response = dns.message.make_response(query)
            if refuse:
                response.set_rcode(5)  # REFUSED
            else:
                soa = dns.rrset.from_text(ZONE, 300, "IN", "SOA", f"ns.{ZONE} a.{ZONE} 1 2 3 4 5")
                response.flags |= dns.flags.AA
                response.answer = [soa, *rrsets, soa]
            wire = response.to_wire()
            conn.sendall(struct.pack("!H", len(wire)) + wire)
        finally:
            conn.close()
            sock.close()

    threading.Thread(target=serve, daemon=True).start()
    return port


async def _axfr(refuse: bool) -> list:
    rrsets = [dns.rrset.from_text(f"{n}.", 300, "IN", "A", "192.0.2.10") for n in PLANTED]
    port = _serve_once(rrsets, refuse=refuse)
    saved = axfr_module.XFR_PORT
    axfr_module.XFR_PORT = port
    try:
        resolver = _StaticResolver({("lab.example", "NS"): ["ns.lab.example."], ("ns.lab.example", "A"): ["127.0.0.1"]})
        return await axfr_module.Axfr().run(dom("lab.example"), ModuleContext(http=None, resolver=resolver))
    finally:
        axfr_module.XFR_PORT = saved


class _Archive(Module):
    """An archive-like source: the field it reads names one host; its payload mentions three more in scope and one
    outside it."""

    name = "wayback"
    accepts = frozenset({D})
    apex_only = True

    async def run(self, entity, ctx):
        payload = json.dumps([
            "https://www.lab.example/login?next=https%3A%2F%2Fsso.lab.example%2F",
            "mail relay: smtp.lab.example; status page at status.lab.example",
            "partner: https://portal.partner.test/",
        ])
        return [Observation(dom("www.lab.example"), "has_subdomain", Evidence.create("wayback", "GET https://web.archive.org/lab", payload))]


async def _mentions() -> tuple[set[str], int]:
    store = Store(":memory:")
    engine = Engine(store, ScopePolicy(domains=["lab.example"]), ctx=None)
    scan = store.create_scan("lab.example")
    store.upsert_entity(scan, dom("lab.example"), ScopeState.IN)
    await engine.run_module(scan, _Archive(), dom("lab.example"))
    mentioned = {e.dst.removeprefix("domain:") for e in store.edges(scan) if e.rel == "mentions"}
    outside = sum(1 for m in mentioned if not m.endswith(".lab.example"))
    return mentioned, outside


async def _live() -> tuple[int, int, int]:
    """(printed, live in the report, printed but not verified) for a small zone with a wildcard."""
    answers = {"lab.example": ("192.0.2.1",), "a.lab.example": ("192.0.2.2",), "b.lab.example": ("192.0.2.3",), "w.lab.example": ("192.0.2.9",)}

    class Lister(Module):
        name = "lister"
        accepts = frozenset({D})
        apex_only = True

        async def run(self, entity, ctx):
            ev = Evidence.create("lister", "GET list", "names")
            return [Observation(dom(n), "has_subdomain", ev) for n in ("a.lab.example", "b.lab.example", "w.lab.example", "gone.lab.example")]

    class Dns(Module):
        name = "dns"
        accepts = frozenset({D})

        async def run(self, entity, ctx):
            await asyncio.sleep(0.005)
            if entity.value in answers:
                ev = Evidence.create("dns", f"DNS A {entity.value}", DnsAnswer("answer", answers[entity.value]).payload())
                return [Observation(Entity(type=EntityType.IP, value=a), "resolves_to", ev) for a in answers[entity.value]]
            return [Fact(Evidence.create("dns", f"DNS A {entity.value}", "NXDOMAIN"))]

    class Wildcard(Module):
        name = "wildcard"
        accepts = frozenset({D})
        apex_only = True

        async def run(self, entity, ctx):
            return [Fact(Evidence.create("dns", f"DNS A wc-probe-000000000000.{entity.value}", "192.0.2.9"))]

    from scrutator.agent.runner import run_agent
    from scrutator.report.build import core_report

    store = Store(":memory:")
    scope = ScopePolicy(domains=["lab.example"])
    engine = Engine(store, scope, ctx=None)
    lines: list[str] = []
    engine.listeners.append(LiveNames(scope, {"lab.example"}, lines.append))
    scan = store.create_scan("lab.example")
    store.set_meta(scan, "scope", json.dumps(scope.to_dict()))
    await run_agent(engine, scan, dom("lab.example"), [Lister(), Dns(), Wildcard()], None)
    printed = {line.split()[1] for line in lines if line.startswith("  live")}
    rows = {r["name"]: r for r in name_states(core_report(store, scan))}
    live = {n for n, r in rows.items() if r["state"] == "live"}
    return len(printed), len(live), sum(1 for n in printed if rows.get(n, {}).get("tier") != "verified") + len(printed ^ live)


async def recall_speed_metrics() -> tuple[dict, list[str]]:
    from scrutator.benchlab.run import _metric

    mentioned, outside = await _mentions()
    zone = await _axfr(refuse=False)
    zone_names = {o.entity.value for o in zone if isinstance(o, Observation)}
    refused = await _axfr(refuse=True)
    refusal_recorded = len(refused) == 1 and isinstance(refused[0], Fact) and refused[0].evidence.payload.startswith(("REFUSED", "FAILED"))
    printed, live, mismatched = await _live()
    expected_mentions = {"sso.lab.example", "smtp.lab.example", "status.lab.example"}
    metrics = {
        "mentions_planted": _metric(len(expected_mentions)),
        "mentions_found": _metric(len(mentioned & expected_mentions), f"= {len(expected_mentions)}", expected_mentions <= mentioned),
        "mentions_outside_scope": _metric(outside, "= 0", outside == 0),
        "axfr_names_planted": _metric(len(PLANTED)),
        "axfr_names_found": _metric(len(zone_names & set(PLANTED)), f"= {len(PLANTED)}", set(PLANTED) <= zone_names),
        "axfr_refusal_recorded": _metric(refusal_recorded, "= true", refusal_recorded),
        "live_names_printed": _metric(printed),
        "live_names_in_report": _metric(live),
        "live_printed_not_verified_or_missing": _metric(mismatched, "= 0", mismatched == 0),
    }
    notes = [
        "fixtures written by the author of the code: the zone transfer runs against a one-shot AXFR responder on 127.0.0.1",
        "the live-name check uses a zone with a wildcard address: a name resolving only to it must never be printed",
    ]
    return metrics, notes
