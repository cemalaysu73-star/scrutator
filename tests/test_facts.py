from scrutator.engine import Engine
from scrutator.model import Entity, EntityType, Evidence, ScopeState
from scrutator.modules.base import Fact, Module, Observation
from scrutator.scope import ScopePolicy
from scrutator.store import Store

D = EntityType.DOMAIN


def dom(value):
    return Entity(type=D, value=value)


def test_scan_evidence_joins_relation_evidence_and_is_per_scan():
    store = Store(":memory:")
    one, two = store.create_scan("a.example.com"), store.create_scan("b.example.com")
    cited = Evidence.create("dns", "DNS A www.example.com", "192.0.2.1")
    fact = Evidence.create("dns", "DNS A ghost.example.com", "NXDOMAIN")
    other = Evidence.create("dns", "DNS A other.example.com", "NXDOMAIN")
    for ev in (cited, fact, other):
        store.add_evidence(ev)
    store.add_edge(one, "domain:www.example.com", "resolves_to", "ip:192.0.2.1", [cited.id])
    store.add_scan_evidence(one, fact.id)
    store.add_scan_evidence(one, fact.id)  # idempotent
    store.add_scan_evidence(two, other.id)
    assert sorted(e.id for e in store.evidence_for_scan(one)) == sorted([cited.id, fact.id])
    assert [e.id for e in store.evidence_for_scan(two)] == [other.id]


def test_evidence_that_is_both_cited_and_a_fact_is_listed_once():
    store = Store(":memory:")
    sid = store.create_scan("example.com")
    ev = Evidence.create("dns", "DNS TXT example.com", '"v=spf1 -all"')
    store.add_evidence(ev)
    store.add_edge(sid, "domain:example.com", "x", "domain:y.example.com", [ev.id])
    store.add_scan_evidence(sid, ev.id)
    assert [e.id for e in store.evidence_for_scan(sid)] == [ev.id]


class Negative(Module):
    name = "negative"
    accepts = frozenset({D})

    async def run(self, entity, ctx):
        return [
            Fact(Evidence.create("dns", f"DNS A {entity.value}", "NXDOMAIN")),
            Observation(dom("www.example.com"), "has_subdomain", Evidence.create("crtsh", "GET https://crt.sh/", "[]")),
        ]


async def test_the_engine_stores_facts_with_the_scan_audits_them_and_adds_no_edge():
    store = Store(":memory:")
    engine = Engine(store, ScopePolicy(domains=["example.com"]), ctx=None)
    sid = store.create_scan("example.com")
    store.upsert_entity(sid, dom("example.com"), ScopeState.IN)
    new = await engine.run_module(sid, Negative(), dom("example.com"))

    assert [e.value for e in new] == ["www.example.com"]  # a fact never makes anything explorable
    assert len(store.edges(sid)) == 1
    fact = Evidence.create("dns", "DNS A example.com", "NXDOMAIN")
    assert fact.id in {e.id for e in store.evidence_for_scan(sid)}
    record = store.audit_log(sid)[-1]
    assert record["event"] == "ok" and fact.id in record["evidence_ids"]
    assert record["observations"] == 2
    assert store.verify_audit(sid)
