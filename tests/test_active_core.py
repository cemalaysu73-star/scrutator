"""Active confirmation, task 1: the guardrail core. Which addresses and ports may be probed (a pure function of the scan's
evidence), the refusals (private, loopback, link-local, reserved, shared platforms), the connection cap, and the gate that
stops everything without an authorisation. No test here opens a connection except to a local listener that counts them."""

import asyncio
import inspect
import json

import pytest

from activefix import FAST, RELAX, config, make_active_store, self_authorisation
from scrutator.active import PORT_REASONS, RISKY_PORTS, WEB_PORTS
from scrutator.active.gate import ActiveRefused, active_authorisation
from scrutator.active.guard import Budget, Limits, refusal, shared_platform
from scrutator.active.plan import plan_active, resolutions
from scrutator.model import Entity, EntityType, Evidence, ScopeState
from scrutator.modules.base import Module, ModuleContext, Observation
from scrutator.packs import load_packs
from scrutator.report.build import core_report
from scrutator.scan import run_scan
from scrutator.scope import ScopePolicy
from scrutator.store import Store

PACKS = load_packs()


def plan_for(names, *, limits=None, relax=RELAX, **kw):
    store, sid = make_active_store(names, **kw)
    return plan_active(core_report(store, sid), PACKS, limits or FAST, relax)


# ------------------------------------------------------------------------------------------------ address refusals


@pytest.mark.parametrize("address,why", [
    ("127.0.0.1", "loopback"), ("127.1.2.3", "loopback"), ("10.0.0.5", "private"), ("172.16.9.9", "private"),
    ("192.168.1.1", "private"), ("169.254.169.254", "link-local"), ("100.64.0.1", "shared address space"),
    ("0.0.0.0", "unspecified"), ("255.255.255.255", "unspecified or broadcast"), ("224.0.0.1", "multicast"),
    ("240.0.0.1", "reserved"), ("198.18.0.1", "reserved"), ("192.0.2.7", "documentation"), ("198.51.100.7", "documentation"),
    ("203.0.113.7", "documentation"), ("::1", "IPv6"), ("2606:4700::1", "IPv6"), ("not-an-ip", "not an IP"),
])
def test_non_public_addresses_are_refused(address, why):
    assert why in refusal(address)


def test_a_public_address_passes_and_relax_is_narrow():
    assert refusal("93.184.216.34") == ""
    assert refusal("127.0.0.1", frozenset({"loopback"})) == "" and "private" in refusal("10.0.0.1", RELAX)
    assert "link-local" in refusal("169.254.169.254", RELAX)  # no relaxation reaches the metadata address
    assert refusal("192.0.2.1", frozenset({"documentation"})) == "" and "loopback" in refusal("127.0.0.1", frozenset({"documentation"}))


def test_ssrf_through_dns_a_public_name_that_resolves_to_an_internal_address_is_never_a_target():
    internal = ["127.0.0.1", "10.0.0.5", "172.16.0.9", "192.168.0.10", "169.254.169.254", "100.64.0.1", "0.0.0.0"]
    plan = plan_for({"www.example.com": internal}, relax=frozenset())
    assert plan.targets == []
    assert sorted(s["ip"] for s in plan.skipped) == sorted(internal)
    assert all(s["kind"] == "refused-address" and s["reason"] for s in plan.skipped)


def test_ipv6_is_recorded_as_skipped_not_probed():
    plan = plan_for({"www.example.com": ["2606:4700:4700::1111"]}, relax=frozenset())
    assert plan.targets == [] and "IPv6" in plan.skipped[0]["reason"]


# ------------------------------------------------------------------------------------------------ target selection


def test_only_addresses_an_in_scope_name_resolves_to_are_targets():
    store, sid = make_active_store({"www.example.com": ["192.0.2.10"], "mail.example.com": ["192.0.2.10", "192.0.2.11"]})
    other = Entity(type=EntityType.DOMAIN, value="www.elsewhere.example")
    store.upsert_entity(sid, other, ScopeState.OUT)
    neighbour = Entity(type=EntityType.IP, value="192.0.2.12")
    store.upsert_entity(sid, neighbour, ScopeState.LINKED)
    ev = Evidence.create("dns", "DNS A www.elsewhere.example", "192.0.2.12")
    store.add_evidence(ev)
    store.add_edge(sid, other.id, "resolves_to", neighbour.id, [ev.id])
    candidate = Entity(type=EntityType.DOMAIN, value="maybe.example.org")
    store.upsert_entity(sid, candidate, ScopeState.CANDIDATE)
    cip = Entity(type=EntityType.IP, value="192.0.2.13")
    store.upsert_entity(sid, cip, ScopeState.LINKED)
    ev2 = Evidence.create("dns", "DNS A maybe.example.org", "192.0.2.13")
    store.add_evidence(ev2)
    store.add_edge(sid, candidate.id, "resolves_to", cip.id, [ev2.id])
    plan = plan_active(core_report(store, sid), PACKS, FAST, RELAX)
    assert [t["ip"] for t in plan.targets] == ["192.0.2.10", "192.0.2.11"]
    assert plan.targets[0]["names"] == ["mail.example.com", "www.example.com"]


def test_an_edge_without_a_dns_record_behind_it_is_not_enough():
    store, sid = make_active_store({})
    name = Entity(type=EntityType.DOMAIN, value="www.example.com")
    ip = Entity(type=EntityType.IP, value="192.0.2.20")
    store.upsert_entity(sid, name, ScopeState.IN)
    store.upsert_entity(sid, ip, ScopeState.LINKED)
    ev = Evidence.create("crtsh", "GET https://crt.sh/?q=x", "[]")
    store.add_evidence(ev)
    store.add_edge(sid, name.id, "resolves_to", ip.id, [ev.id])
    assert plan_active(core_report(store, sid), PACKS, FAST, RELAX).targets == []


def test_a_range_or_the_seed_alone_never_makes_a_target():
    store, sid = make_active_store({})
    policy_ip = Entity(type=EntityType.IP, value="192.0.2.30")
    store.upsert_entity(sid, policy_ip, ScopeState.IN)  # an address in the scope with no name resolving to it
    assert plan_active(core_report(store, sid), PACKS, FAST, RELAX).targets == []


def test_names_for_tls_and_http_are_capped_per_address_apex_first():
    names = {n: ["192.0.2.10"] for n in ("a.b.example.com", "www.example.com", "example.com", "mail.example.com", "z.example.com")}
    target = plan_for(names).targets[0]
    assert target["probe_names"] == ["example.com", "mail.example.com", "www.example.com"] and len(target["names"]) == 5


# ------------------------------------------------------------------------------------------------ ports


def test_ports_are_the_passive_ones_plus_the_fixed_list_and_web():
    target = plan_for({"www.example.com": ["192.0.2.10"]}, ports={"192.0.2.10": [21, 23, 7777, 80]}).targets[0]
    ports = {p["port"] for p in target["ports"]}
    assert ports == set(RISKY_PORTS) | set(WEB_PORTS) | {7777}
    assert target["passive_ports"] == [21, 23, 80, 7777]
    assert any("passive source lists it open" in p["why"] for p in target["ports"] if p["port"] == 23)
    assert all(p["why"] for p in target["ports"]) and set(PORT_REASONS) == set(RISKY_PORTS) | set(WEB_PORTS)


def test_the_connect_cap_is_shared_across_addresses_and_the_rest_is_recorded():
    limits = Limits(max_connections=20, tcp_share=0.5, rate_per_second=50.0)  # ten connect checks
    names = {"a.example.com": ["192.0.2.10"], "b.example.com": ["192.0.2.11"]}
    many = list(range(9000, 9040))
    plan = plan_for(names, limits=limits, ports={"192.0.2.10": many, "192.0.2.11": [23]})
    per_ip = {t["ip"]: len(t["ports"]) for t in plan.targets}
    assert sum(per_ip.values()) == 10 and per_ip["192.0.2.11"] >= 4  # the long list did not take the other address's checks
    assert {t["ip"]: {p["port"] for p in t["ports"]} for t in plan.targets}["192.0.2.11"] >= {23}
    assert plan.over_cap and all(o["port"] not in {p["port"] for t in plan.targets if t["ip"] == o["ip"] for p in t["ports"]} for o in plan.over_cap)


def test_risky_ports_listed_by_a_passive_source_come_before_everything_else():
    limits = Limits(max_connections=10, tcp_share=0.3, rate_per_second=50.0)  # three connect checks
    target = plan_for({"www.example.com": ["192.0.2.10"]}, limits=limits, ports={"192.0.2.10": [23, 3306, 9999]}).targets[0]
    assert {p["port"] for p in target["ports"]} == {23, 3306, 80}


# ------------------------------------------------------------------------------------------------ shared platforms


def example_hit(example):
    import ipaddress

    if example[:2].upper() == "AS" and example[2:].isdigit():
        return shared_platform(PACKS, address="93.184.216.34", asns=[example])
    try:
        ipaddress.ip_address(example)
        return shared_platform(PACKS, address=example)
    except ValueError:
        return shared_platform(PACKS, address="93.184.216.34", hosts=[example])


def test_every_shared_platform_entry_recognises_its_own_examples():
    assert PACKS.shared
    for entry in PACKS.shared:
        assert entry.examples, entry.id
        for example in entry.examples:
            hit = example_hit(example)
            assert hit is not None and hit[0].id == entry.id, (entry.id, example)


@pytest.mark.parametrize("kwargs,platform", [
    ({"names": {"www.example.com": ["104.16.1.1"]}}, "Cloudflare"),
    ({"names": {"www.example.com": ["192.0.2.10"]}, "asns": {"192.0.2.10": 13335}}, "Cloudflare"),
    ({"names": {"www.example.com": ["192.0.2.10"]}, "cnames": {"www.example.com": "cname.vercel-dns.com"}}, "Vercel"),
    ({"names": {"www.example.com": ["192.0.2.10"]}, "hostnames": {"192.0.2.10": ["server-1-2-3-4.fra1.r.cloudfront.net"]}}, "Amazon CloudFront"),
    ({"names": {"www.example.com": ["192.0.2.10"]}, "netnames": {"192.0.2.10": "FASTLY"}}, "Fastly"),
    ({"names": {"www.example.com": ["185.199.108.153"]}}, "GitHub Pages"),
])
def test_an_address_on_a_shared_platform_is_skipped_with_the_reason(kwargs, platform):
    plan = plan_for(kwargs.pop("names"), **kwargs)
    assert plan.targets == []
    skip = plan.skipped[0]
    assert skip["kind"] == "shared-platform" and skip["platform"] == platform and skip["signal"] and "not probed" in skip["reason"]
    assert isinstance(skip["verified"], bool) and skip["evidence_ids"]


def test_dedicated_hosting_is_not_a_shared_platform():
    plan = plan_for({"www.example.com": ["192.0.2.10"]}, asns={"192.0.2.10": 24940}, netnames={"192.0.2.10": "HETZNER-RZ-FKS"})
    assert [t["ip"] for t in plan.targets] == ["192.0.2.10"] and plan.skipped == []


def test_a_cloudflare_cname_on_a_private_looking_chain_still_skips_nothing_it_should_not():
    # one name behind a platform, another on its own address: only the first is skipped
    plan = plan_for({"a.example.com": ["192.0.2.10"], "b.example.com": ["192.0.2.11"]},
                    cnames={"a.example.com": "a.herokuapp.com"})
    assert [t["ip"] for t in plan.targets] == ["192.0.2.11"] and plan.skipped[0]["platform"] == "Heroku"


def test_the_plan_is_deterministic_and_json_serialisable():
    one = plan_for({"www.example.com": ["192.0.2.10"], "mail.example.com": ["192.0.2.11"]}, ports={"192.0.2.11": [25]})
    two = plan_for({"mail.example.com": ["192.0.2.11"], "www.example.com": ["192.0.2.10"]}, ports={"192.0.2.11": [25]})
    assert json.dumps(one.to_dict(), sort_keys=True) == json.dumps(two.to_dict(), sort_keys=True)


# ------------------------------------------------------------------------------------------------ limits and budget


def test_limits_are_validated():
    with pytest.raises(ValueError):
        Limits(max_connections=0)
    with pytest.raises(ValueError):
        Limits(concurrency=99)
    with pytest.raises(ValueError):
        Limits(rate_per_second=1000)


async def test_the_budget_refuses_after_the_cap_and_paces_connections():
    sleeps = []
    clock = [0.0]

    async def sleep(seconds):
        sleeps.append(seconds)
        clock[0] += seconds

    budget = Budget(Limits(max_connections=3, rate_per_second=2.0), clock=lambda: clock[0], sleep=sleep)
    assert [await budget.take() for _ in range(5)] == [True, True, True, False, False]
    assert budget.used == 3 and budget.exhausted
    assert sleeps == pytest.approx([0.5, 0.5])  # connections start 0.5 s apart at 2 a second


# ------------------------------------------------------------------------------------------------ the gate


def test_the_gate_needs_an_authorisation_that_covers_active_testing():
    with pytest.raises(ActiveRefused, match="needs an authorisation"):
        active_authorisation([])
    with pytest.raises(ActiveRefused, match="self-assessment"):
        active_authorisation(self_authorisation(active=False))
    with pytest.raises(ActiveRefused, match="active_testing"):
        active_authorisation([{"event": "engagement", "sha256": "0" * 64}])
    assert active_authorisation(self_authorisation())["active"] is True
    assert active_authorisation([{"event": "engagement", "active_testing": True}])["active_testing"] is True


class Resolving(Module):
    name = "fakedns"
    accepts = frozenset({EntityType.DOMAIN})

    def __init__(self, table):
        self.table = table

    async def run(self, entity, ctx):
        out = []
        for ip in self.table.get(entity.value, []):
            out.append(Observation(Entity(type=EntityType.IP, value=ip), "resolves_to", Evidence.create("dns", f"DNS A {entity.value}", ip)))
        return out


def listener_counter():
    """A local TCP listener that counts connections: any probe of 127.0.0.1 shows up here."""
    state = {"connections": 0}

    async def handle(reader, writer):
        state["connections"] += 1
        writer.close()

    return state, handle


async def scan(store_path, table, *, pre_audit, active, seed="example.com"):
    store = Store(store_path)
    ctx = ModuleContext(http=None, resolver=None)
    result = await run_scan(
        Entity(type=EntityType.DOMAIN, value=seed), ScopePolicy(domains=[seed]), store, ctx, modules=[Resolving(table)],
        pre_audit=pre_audit, active=active, source_policy=None,
    )
    return store, result


async def test_without_an_authorisation_nothing_is_created_and_nothing_connects():
    state, handle = listener_counter()
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    try:
        for pre in (None, [], self_authorisation(active=False)):
            store = Store(":memory:")
            with pytest.raises(ActiveRefused):
                await run_scan(
                    Entity(type=EntityType.DOMAIN, value="example.com"), ScopePolicy(domains=["example.com"]), store,
                    ModuleContext(http=None, resolver=None), modules=[Resolving({"example.com": ["127.0.0.1"]})],
                    pre_audit=pre, active=config(),
                )
            assert store.scans() == []  # the scan was not even created
    finally:
        server.close()
    assert state["connections"] == 0


async def test_the_authorisation_and_the_active_record_precede_every_lookup_and_the_plan_precedes_every_connection(tmp_path):
    store, _ = await scan(":memory:", {"example.com": ["192.0.2.10"]}, pre_audit=self_authorisation(), active=config())
    sid = store.scans()[0]["id"]
    log = store.audit_log(sid)
    events = [r.get("event") for r in log]
    first_lookup = next(i for i, r in enumerate(log) if r.get("module"))
    assert events.index("self_attestation") < events.index("active_confirmation_authorised") < first_lookup
    authorised = log[events.index("active_confirmation_authorised")]
    assert authorised["limits"]["max_connections"] == FAST.max_connections
    assert authorised["fixed_ports"] == [*RISKY_PORTS, *WEB_PORTS] and authorised["proxy"] is None and authorised["test_mode"]
    assert "login or credential attempts" in authorised["never"]
    plan_record = log[events.index("active_plan")]
    assert plan_record["targets"] == ["192.0.2.10"] and events.index("active_plan") > first_lookup
    plan_evidence = store.get_evidence(plan_record["evidence_id"])
    assert plan_evidence.source == "active" and plan_evidence.request == "ACTIVE PLAN example.com"
    assert json.loads(plan_evidence.payload)["targets"][0]["ip"] == "192.0.2.10"
    assert events[-1] == "active_done" and store.verify_audit(sid)


async def test_a_run_without_active_has_no_active_records():
    store, _ = await scan(":memory:", {"example.com": ["192.0.2.10"]}, pre_audit=self_authorisation(), active=None)
    sid = store.scans()[0]["id"]
    assert not [r for r in store.audit_log(sid) if "active" in str(r.get("event"))]
    assert all(e.source != "active" for e in store.evidence_for_scan(sid))


# ------------------------------------------------------------------------------------------------ MCP


def test_mcp_cannot_reach_active_confirmation(monkeypatch, tmp_path):
    from scrutator import mcp_tools

    seen = {}

    async def spy(*args, **kwargs):
        seen.update(kwargs)
        raise RuntimeError("stop")

    monkeypatch.setattr(mcp_tools, "run_scan", spy)
    scope = tmp_path / "scope.yaml"
    scope.write_text("domains: [example.com]\n", encoding="utf-8")
    tools = mcp_tools.ToolSet(tmp_path / "db.sqlite", scope_file=scope, allow_scan=True)
    with pytest.raises(RuntimeError):
        asyncio.run(tools.scan("example.com"))
    assert seen.get("active") is None and not seen.get("allow_active") and not seen.get("pre_audit")
    parameters = set(inspect.signature(mcp_tools.ToolSet.scan).parameters)
    assert not {p for p in parameters if any(w in p.lower() for w in ("active", "port", "proxy", "probe", "engagement"))}


@pytest.fixture
def untouched_logging():
    """Building an MCP server configures logging (levels, handlers); give it back as it was so no later test sees the change."""
    import logging

    loggers = [logging.getLogger(n) for n in ("", "httpx", "mcp", "httpcore")]
    saved = [(lg, lg.level, list(lg.handlers), lg.propagate, lg.disabled) for lg in loggers]
    yield
    for lg, level, handlers, propagate, disabled in saved:
        lg.setLevel(level)
        lg.handlers[:] = handlers
        lg.propagate, lg.disabled = propagate, disabled


def test_the_mcp_server_offers_no_tool_or_parameter_for_it(tmp_path, untouched_logging):
    pytest.importorskip("mcp")
    from scrutator.mcp_server import build_server
    from scrutator.mcp_tools import ToolSet

    server = build_server(ToolSet(tmp_path / "db.sqlite", scope_file=tmp_path / "s.yaml", allow_scan=True, allow_promote=True))
    tools = asyncio.run(server.list_tools())
    text = json.dumps([{"name": t.name, "schema": t.model_dump(by_alias=True)["inputSchema"]} for t in tools]).lower()
    for word in ("active", "probe", "connect", "proxy", "engagement", "self_attest"):
        assert word not in text, word
