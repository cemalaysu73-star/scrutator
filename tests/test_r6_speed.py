"""R6 task 1: speed people feel.

- the live name list prints a name the moment the report's own test would call it live, never one the report would not
  (wildcard-covered names are held back, the apex's probe is waited for);
- lookups waiting for a slot are handed it best-vouched name first;
- `scrutator quick` asks only the name sources and DNS, within its budget, and writes a report and a bundle that verify;
- RDAP of a public address goes to the registry that holds it, an earlier scan's network record is reused;
- RIPEstat and the announcing prefix are asked once per network, and the address table still describes every address.
"""

import asyncio
import json
from contextlib import asynccontextmanager

import httpx
import pytest
import respx
from typer.testing import CliRunner

from scrutator import cli
from scrutator.engine import Engine, _Slots
from scrutator.exposure import exposure
from scrutator.livenames import LiveNames
from scrutator.model import Entity, EntityType, Evidence, ScopeState
from scrutator.modules.asn import Asn
from scrutator.modules.base import Fact, Module, ModuleContext, Observation
from scrutator.modules.rdap import Rdap, rir_url
from scrutator.modules.ripestat import RipeStat
from scrutator.names import name_states
from scrutator.resolver import DnsAnswer
from scrutator.scope import ScopePolicy
from scrutator.store import Store

D, IP = EntityType.DOMAIN, EntityType.IP


def dom(value):
    return Entity(type=D, value=value)


def ip(value):
    return Entity(type=IP, value=value)


class Named:
    def __init__(self, name):
        self.name = name


def dns_obs(name, *addresses):
    evidence = Evidence.create("dns", f"DNS A {name}", DnsAnswer("answer", tuple(addresses)).payload())
    return [Observation(ip(a), "resolves_to", evidence) for a in addresses]


def probe_facts(apex, *addresses):
    if not addresses:
        return [Fact(Evidence.create("dns", f"DNS A wc-probe-000000000000.{apex}", "NXDOMAIN"))]
    return [Fact(Evidence.create("dns", f"DNS A wc-probe-000000000000.{apex}", DnsAnswer("answer", tuple(addresses)).payload()))]


def watcher(lines, probes=True):
    clock = iter(float(n) for n in range(1000))
    return LiveNames(ScopePolicy(domains=["example.com"]), {"example.com"}, lines.append, probes_expected=probes,
                     clock=lambda: next(clock), started=0.0)


# ------------------------------------------------------------------------------------------ live names


def test_a_name_waits_for_the_wildcard_probe_and_a_wildcard_only_name_is_never_printed():
    lines = []
    live = watcher(lines)
    live(Named("dns"), dom("www.example.com"), dns_obs("www.example.com", "192.0.2.1"))
    live(Named("dns"), dom("ghost.example.com"), dns_obs("ghost.example.com", "192.0.2.9"))
    assert lines == []  # the probe of example.com has not answered
    live(Named("wildcard"), dom("example.com"), probe_facts("example.com", "192.0.2.9"))
    assert [line.split()[1] for line in lines] == ["www.example.com"]
    live.on_names_settled()
    assert lines[-1].startswith("names: 1 live name in") and "1 resolve only to a wildcard address" in lines[-1]


def test_the_apex_needs_no_probe_and_a_failed_probe_holds_nothing_back():
    lines = []
    live = watcher(lines)
    live(Named("dns"), dom("example.com"), dns_obs("example.com", "192.0.2.1"))
    assert lines and lines[0].split()[1] == "example.com"
    live(Named("dns"), dom("a.example.com"), dns_obs("a.example.com", "192.0.2.2"))
    live(Named("wildcard"), dom("example.com"), [])  # the probe failed: nothing recorded, nothing to compare
    assert [line.split()[1] for line in lines] == ["example.com", "a.example.com"]
    assert live.first_subdomain_at is not None


def test_out_of_scope_names_and_names_without_an_address_are_not_printed_and_claims_are_counted():
    lines = []
    live = watcher(lines, probes=False)
    lister = Named("subdomaincenter")
    evidence = Evidence.create("subdomaincenter", "GET x", "a")
    live(lister, dom("example.com"), [Observation(dom("old.example.com"), "has_subdomain", evidence)])
    live(Named("dns"), dom("old.example.com"), [Fact(Evidence.create("dns", "DNS A old.example.com", "NXDOMAIN"))])
    live(Named("dns"), dom("cdn.thirdparty.net"), dns_obs("cdn.thirdparty.net", "192.0.2.3"))
    live.on_names_settled()
    live.on_names_settled()  # said once
    assert lines == ["names: 0 live names in 0.0 s; 1 more named by sources only (claims until DNS or a certificate agrees; see the report)."]


async def test_every_name_the_list_prints_is_verified_in_the_report_and_every_live_name_is_printed():
    """Run a scan through the engine with the watcher attached; compare with the report's own name states."""
    class Lister(Module):
        name = "lister"
        accepts = frozenset({D})
        apex_only = True

        async def run(self, entity, ctx):
            ev = Evidence.create("lister", "GET list", "names")
            return [Observation(dom(n), "has_subdomain", ev) for n in ("a.example.com", "b.example.com", "w.example.com", "gone.example.com")]

    answers = {"example.com": ("192.0.2.1",), "a.example.com": ("192.0.2.2",), "b.example.com": ("192.0.2.3", "192.0.2.9"), "w.example.com": ("192.0.2.9",)}

    class Dns(Module):
        name = "dns"
        accepts = frozenset({D})

        async def run(self, entity, ctx):
            await asyncio.sleep(0.01)
            if entity.value in answers:
                return dns_obs(entity.value, *answers[entity.value])
            return [Fact(Evidence.create("dns", f"DNS A {entity.value}", "NXDOMAIN"))]

    class Wildcard(Module):
        name = "wildcard"
        accepts = frozenset({D})
        apex_only = True

        async def run(self, entity, ctx):
            await asyncio.sleep(0.05)
            return probe_facts(entity.value, "192.0.2.9")

    from scrutator.agent.runner import run_agent
    from scrutator.report.build import core_report

    store = Store(":memory:")
    scope = ScopePolicy(domains=["example.com"])
    engine = Engine(store, scope, ctx=None)
    lines = []
    live = LiveNames(scope, {"example.com"}, lines.append, probes_expected=True)
    engine.listeners.append(live)
    scan = store.create_scan("example.com")
    store.set_meta(scan, "scope", json.dumps(scope.to_dict()))
    await run_agent(engine, scan, dom("example.com"), [Lister(), Dns(), Wildcard()], None)
    printed = {line.split()[1] for line in lines if line.startswith("  live")}
    rows = {row["name"]: row for row in name_states(core_report(store, scan))}
    assert printed == {name for name, row in rows.items() if row["state"] == "live"} == {"example.com", "a.example.com", "b.example.com"}
    assert all(rows[name]["tier"] == "verified" for name in printed)
    assert rows["w.example.com"]["state"] == "wildcard"
    assert any(line.startswith("names: 3 live names") for line in lines)


# ------------------------------------------------------------------------------------------ ranked slots


async def test_a_freed_slot_goes_to_the_best_ranked_waiter_and_ranks_are_read_at_hand_over():
    slots = _Slots(1)
    order = []
    rank = {"a": 0, "b": 0, "c": 0}

    async def job(name):
        await slots.acquire(lambda: rank[name])
        order.append(name)
        await asyncio.sleep(0.01)
        slots.release()

    holder = asyncio.ensure_future(job("first"))
    rank["first"] = 0
    await asyncio.sleep(0)
    waiters = [asyncio.ensure_future(job(n)) for n in ("a", "b", "c")]
    await asyncio.sleep(0)
    rank["c"] = -5  # a second source named `c` while it waited
    await asyncio.gather(holder, *waiters)
    assert order == ["first", "c", "a", "b"]


async def test_a_cancelled_waiter_does_not_leak_a_slot():
    slots = _Slots(1)
    await slots.acquire(lambda: 0)
    waiting = asyncio.ensure_future(slots.acquire(lambda: 0))
    await asyncio.sleep(0)
    waiting.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiting
    slots.release()
    await asyncio.wait_for(slots.acquire(lambda: 0), 1)  # the slot came back


async def test_names_vouched_by_more_sources_are_resolved_first():
    class Lister(Module):
        accepts = frozenset({D})
        apex_only = True

        def __init__(self, name, names, weight):
            self.name, self.names, self.name_weight = name, names, weight

        async def run(self, entity, ctx):
            ev = Evidence.create(self.name, f"GET {self.name}", ",".join(self.names))
            return [Observation(dom(n), "has_subdomain", ev) for n in self.names]

    started = []

    class Resolve(Module):
        name = "resolve"
        accepts = frozenset({D})
        concurrency = 1

        async def run(self, entity, ctx):
            started.append(entity.value)
            await asyncio.sleep(0.005)
            return []

    from scrutator.agent.runner import run_agent

    store = Store(":memory:")
    engine = Engine(store, ScopePolicy(domains=["example.com"]), ctx=None)
    scan = store.create_scan("example.com")
    many = [f"list{n}.example.com" for n in range(20)]
    await run_agent(engine, scan, dom("example.com"), [
        Lister("aggregator", many + ["www.example.com"], 1), Lister("certs", ["www.example.com"], 3), Resolve(),
    ], None)
    # `www` is named by a certificate source too: it is resolved before the twenty names only a list gives
    assert started.index("www.example.com") <= 2


# ------------------------------------------------------------------------------------------ the engine's timeout cap


async def test_the_timeout_cap_cuts_a_slow_lookup_and_records_it_as_an_error():
    class Slow(Module):
        name = "slow"
        accepts = frozenset({D})

        async def run(self, entity, ctx):
            await asyncio.sleep(5)
            return []

    store = Store(":memory:")
    engine = Engine(store, ScopePolicy(domains=["example.com"]), ctx=None, timeout_cap=0.05)
    scan = store.create_scan("example.com")
    store.upsert_entity(scan, dom("example.com"), ScopeState.IN)
    seen = []
    engine.listeners.append(lambda module, entity, obs: seen.append((module.name, obs)))
    assert await engine.run_module(scan, Slow(), dom("example.com")) == []
    assert [r["event"] for r in store.audit_log(scan)] == ["error"]
    assert seen == [("slow", [])]  # a listener hears of a failed lookup too


async def test_a_listener_that_raises_is_dropped_and_the_scan_goes_on():
    class Quick(Module):
        name = "quick"
        accepts = frozenset({D})

        async def run(self, entity, ctx):
            return [Observation(dom("a.example.com"), "has_subdomain", Evidence.create("quick", "q", "a"))]

    def broken(*_):
        raise RuntimeError("display failed")

    store = Store(":memory:")
    engine = Engine(store, ScopePolicy(domains=["example.com"]), ctx=None)
    engine.listeners.append(broken)
    scan = store.create_scan("example.com")
    store.upsert_entity(scan, dom("example.com"), ScopeState.IN)
    found = await engine.run_module(scan, Quick(), dom("example.com"))
    assert [e.value for e in found] == ["a.example.com"] and engine.listeners == []


# ------------------------------------------------------------------------------------------ RDAP: registries, reuse


def network(start, end, name="NET-EXAMPLE"):
    return {"handle": "NET-1", "name": name, "startAddress": start, "endAddress": end}


def test_public_addresses_go_to_the_registry_that_holds_them_and_reserved_ones_do_not():
    assert rir_url("104.20.44.163") == "https://rdap.arin.net/registry/ip/104.20.44.163"
    assert rir_url("93.184.216.34") == "https://rdap.db.ripe.net/ip/93.184.216.34"
    assert rir_url("1.1.1.1") == "https://rdap.apnic.net/ip/1.1.1.1"
    assert rir_url("2606:50c0:8003::153").startswith("https://rdap.arin.net/registry/ip/")
    for reserved in ("198.51.100.7", "10.0.0.1", "2001:db8::1", "127.0.0.1", "not an address"):
        assert rir_url(reserved) is None


async def test_rdap_asks_the_registry_directly_and_covers_the_rest_of_the_network(http):
    ctx = ModuleContext(http=http, resolver=None)
    with respx.mock(assert_all_called=False) as router:
        direct = router.get("https://rdap.arin.net/registry/ip/104.20.44.163").mock(
            return_value=httpx.Response(200, json=network("104.16.0.0", "104.31.255.255", "CLOUDFLARENET")))
        redirector = router.get(url__regex=r"https://rdap\.org/.*").mock(return_value=httpx.Response(500))
        a = await Rdap().run(ip("104.20.44.163"), ctx)
        b = await Rdap().run(ip("104.20.45.163"), ctx)
    assert direct.call_count == 1 and redirector.call_count == 0
    assert a[0].evidence.request == "GET https://rdap.arin.net/registry/ip/104.20.44.163"
    assert a[0].evidence.id == b[0].evidence.id and b[0].entity.value == "CLOUDFLARENET"


async def test_addresses_of_one_lane_take_turns_only_while_answers_name_a_network(http):
    ctx = ModuleContext(http=http, resolver=None)
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=r"https://rdap\.arin\.net/registry/ip/.*").mock(return_value=httpx.Response(200, json={"name": "NO-RANGE"}))
        await asyncio.gather(*(Rdap().run(ip(f"104.20.44.{n}"), ctx) for n in range(1, 6)))
    assert route.call_count == 5  # no range to share: every address asked, in parallel once the first named none


async def test_a_repeat_scan_reuses_a_recent_network_record_from_the_same_database(tmp_path):
    from scrutator.scan import run_scan

    store = Store(tmp_path / "s.db")
    old = Evidence.create("rdap", "GET https://rdap.arin.net/registry/ip/104.20.44.1", json.dumps(network("104.16.0.0", "104.31.255.255", "CLOUDFLARENET")))
    store.add_evidence(old)

    asked = []

    class Seed(Module):
        name = "dns"
        accepts = frozenset({D})

        async def run(self, entity, ctx):
            return dns_obs(entity.value, "104.20.44.163") if entity.value == "example.com" else []

    class Wrapped(Rdap):
        name = "rdap"

        async def _ask(self, entity, ctx):
            asked.append(entity.value)
            return []

    ctx = ModuleContext(http=None, resolver=None)
    scan_id, _ = await run_scan(dom("example.com"), ScopePolicy(domains=["example.com"]), store, ctx, modules=[Seed(), Wrapped()])
    assert asked == ["example.com"]  # the domain was asked; the address rests on the stored network record
    edges = [(e.rel, e.evidence_ids) for e in store.edges(scan_id) if e.rel == "netblock_owner"]
    assert edges == [("netblock_owner", (old.id,))]
    assert any(r.get("event") == "rdap_reuse_offered" and r["records"] == 1 for r in store.audit_log(scan_id))
    assert store.get_evidence(old.id).collected_at == old.collected_at  # it keeps its own collection time


# ------------------------------------------------------------------------------------------ RIPEstat, prefixes


def prefix_body(resource, asn=13335, related=0):
    return {"data": {"resource": resource, "announced": True, "asns": [{"asn": asn, "holder": "X"}], "related_prefixes": [], "actual_num_related": related}}


async def test_an_address_inside_an_announced_prefix_with_no_more_specifics_reuses_the_answer(http):
    ctx = ModuleContext(http=http, resolver=None)
    with respx.mock() as router:
        route = router.get("https://stat.ripe.net/data/prefix-overview/data.json").mock(return_value=httpx.Response(200, json=prefix_body("104.20.32.0/20")))
        a = await Asn().run(ip("104.20.44.163"), ctx)
        b = await Asn().run(ip("104.20.45.1"), ctx)
    assert route.call_count == 1 and a[0].evidence.id == b[0].evidence.id and b[0].entity.value == "AS13335"


async def test_a_prefix_with_more_specifics_inside_covers_nothing(http):
    ctx = ModuleContext(http=http, resolver=None)
    with respx.mock() as router:
        route = router.get("https://stat.ripe.net/data/prefix-overview/data.json").mock(return_value=httpx.Response(200, json=prefix_body("104.20.32.0/20", related=2)))
        await Asn().run(ip("104.20.44.163"), ctx)
        await Asn().run(ip("104.20.45.1"), ctx)
    assert route.call_count == 2


ABUSE = "https://stat.ripe.net/data/abuse-contact-finder/data.json"
WHOIS = "https://stat.ripe.net/data/whois/data.json"


def whois_body(*rows):
    return {"data": {"records": [[{"key": k, "value": v} for k, v in rows]]}}


async def test_ripestat_asks_once_per_network_and_the_address_table_still_describes_every_address(http):
    ctx = ModuleContext(http=http, resolver=None)
    with respx.mock() as router:
        abuse = router.get(ABUSE).mock(return_value=httpx.Response(200, json={"data": {"abuse_contacts": ["abuse@example.net"]}}))
        whois = router.get(WHOIS).mock(return_value=httpx.Response(200, json=whois_body(
            ("NetRange", "104.16.0.0 - 104.31.255.255"), ("CIDR", "104.16.0.0/12"), ("netname", "CLOUDFLARENET"), ("country", "US"))))
        first = await RipeStat().run(ip("104.20.44.163"), ctx)
        second = await RipeStat().run(ip("104.20.45.1"), ctx)
        outside = await RipeStat().run(ip("172.64.149.246"), ctx)
    assert abuse.call_count == whois.call_count == 2 and second == [] and len(first) == len(outside) == 2
    report = {"entities": [{"type": "ip", "value": v, "state": "linked"} for v in ("104.20.44.163", "104.20.45.1", "172.64.149.246")],
              "evidence": {f.evidence.id: {"source": f.evidence.source, "request": f.evidence.request, "payload": f.evidence.payload} for f in first + outside}}
    rows = {row["ip"]: row for row in exposure(report)}
    assert rows["104.20.45.1"]["abuse_contacts"] == ["abuse@example.net"] and rows["104.20.45.1"]["netname"] == "CLOUDFLARENET"
    assert rows["104.20.45.1"]["inherited_from"] == "104.20.44.163"
    assert set(rows["104.20.45.1"]["evidence_ids"]) == {f.evidence.id for f in first}
    assert "inherited_from" not in rows["104.20.44.163"]


def test_an_address_outside_every_recorded_range_inherits_nothing():
    report = {"entities": [{"type": "ip", "value": "203.0.113.5", "state": "linked"}], "evidence": {
        "w": {"source": "ripestat", "request": f"GET {WHOIS}?resource=198.51.100.1&sourceapp=scrutator", "payload": json.dumps([{"key": "inetnum", "value": "198.51.100.0 - 198.51.100.255"}])}}}
    assert exposure(report) == []


# ------------------------------------------------------------------------------------------ quick


runner = CliRunner()


def test_quick_asks_name_sources_and_dns_only_within_its_budget_and_writes_a_bundle_that_verifies(tmp_path, monkeypatch):
    captured = {}

    @asynccontextmanager
    async def fake_context():
        yield ModuleContext(http=None, resolver=None)

    async def fake_run_scan(seed, scope, store, ctx, **kwargs):
        captured.update(kwargs)
        scan_id = store.create_scan(seed.value)
        store.set_meta(scan_id, "scope", json.dumps(scope.to_dict()))
        from scrutator.modules.registry import load_builtin_modules

        record = kwargs["source_policy"].record(load_builtin_modules())
        store.set_meta(scan_id, "source_policy", json.dumps(record, sort_keys=True))
        store.append_audit(scan_id, {"event": "source_policy", **record})
        store.upsert_entity(scan_id, seed, ScopeState.IN)
        www = dom("www.example.com")
        store.upsert_entity(scan_id, www, ScopeState.IN)
        ev = Evidence.create("dns", "DNS A www.example.com", "192.0.2.1")
        store.add_evidence(ev)
        store.upsert_entity(scan_id, ip("192.0.2.1"), ScopeState.LINKED)
        store.add_edge(scan_id, www.id, "resolves_to", ip("192.0.2.1").id, [ev.id])
        store.append_audit(scan_id, {"event": "ok", "module": "dns", "entity": www.id, "evidence_ids": [ev.id]})
        for listener in kwargs["listeners"]:
            listener(type("M", (), {"name": "wildcard"})(), seed, [])
            listener(type("M", (), {"name": "dns"})(), www, dns_obs("www.example.com", "192.0.2.1"))
        from scrutator.agent.runner import AgentStats
        return scan_id, AgentStats()

    monkeypatch.setattr(cli, "open_context", fake_context)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    keys = tmp_path / "keys"
    assert runner.invoke(cli.app, ["keygen", "--key-dir", str(keys)]).exit_code == 0
    out = tmp_path / "q"
    result = runner.invoke(cli.app, ["quick", "example.com", "--out", str(out), "--bundle", "--key-dir", str(keys), "--budget", "6"])
    assert result.exit_code == 0, result.output
    policy = captured["source_policy"]
    allowed = set(policy.allow)
    assert {"crtsh", "certspotter", "hackertarget", "subdomaincenter", "urlscan", "wayback", "commoncrawl", "dns", "wildcard"} <= allowed
    assert not allowed & {"rdap", "asn", "ripestat", "internetdb", "mnemonic", "brand"}
    assert captured["deadline"].seconds == 6 and captured["timeout_cap"] == 5.0
    assert "  live  www.example.com" in result.output
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert [r["name"] for r in report["names"] if r["tier"] == "verified"] == ["www.example.com"]
    from scrutator.bundle.verify import verify_bundle

    assert verify_bundle(out / "proof.scrutator").ok


def test_quick_refuses_an_address():
    result = runner.invoke(cli.app, ["quick", "192.0.2.1"])
    assert result.exit_code == 2 and "give a domain" in result.output
