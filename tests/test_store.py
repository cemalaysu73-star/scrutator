import pytest

from scrutator.model import Entity, EntityType, Evidence, ScopeState
from scrutator.store import Store


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


def dom(value):
    return Entity(type=EntityType.DOMAIN, value=value)


def test_scan_roundtrip(store):
    sid = store.create_scan("example.com")
    seed, started_at = store.get_scan(sid)
    assert seed == "example.com"
    assert started_at


def test_upsert_entity_reports_insert_and_promotion(store):
    sid = store.create_scan("example.com")
    ip = Entity(type=EntityType.IP, value="192.0.2.1")
    assert store.upsert_entity(sid, ip, ScopeState.OUT) is True
    assert store.upsert_entity(sid, ip, ScopeState.OUT) is False
    assert store.upsert_entity(sid, ip, ScopeState.LINKED) is True
    assert store.upsert_entity(sid, ip, ScopeState.OUT) is False
    assert store.scope_state(sid, ip.id) is ScopeState.LINKED
    assert store.scope_state(sid, "domain:nope.com") is None


def test_entities_are_listed_with_state(store):
    sid = store.create_scan("example.com")
    store.upsert_entity(sid, dom("b.example.com"), ScopeState.IN)
    store.upsert_entity(sid, dom("a.other.net"), ScopeState.OUT)
    listed = store.entities(sid)
    assert [(s.entity.value, s.state) for s in listed] == [
        ("a.other.net", ScopeState.OUT),
        ("b.example.com", ScopeState.IN),
    ]


def test_edges_merge_evidence_from_several_sources(store):
    sid = store.create_scan("example.com")
    a, b = dom("example.com"), dom("www.example.com")
    for e in (a, b):
        store.upsert_entity(sid, e, ScopeState.IN)
    ev1 = Evidence.create("crtsh", "GET x", "p1")
    ev2 = Evidence.create("wayback", "GET y", "p2")
    store.add_evidence(ev1)
    store.add_evidence(ev2)
    store.add_edge(sid, a.id, "has_subdomain", b.id, [ev1.id])
    store.add_edge(sid, a.id, "has_subdomain", b.id, [ev2.id, ev1.id])
    edges = store.edges(sid)
    assert len(edges) == 1
    assert set(edges[0].evidence_ids) == {ev1.id, ev2.id}


def test_evidence_is_deduplicated_and_retrievable(store):
    ev = Evidence.create("dns", "DNS A x", "1.2.3.4")
    store.add_evidence(ev)
    store.add_evidence(ev)
    assert store.get_evidence(ev.id) == ev
    assert store.get_evidence("0" * 64) is None


def test_evidence_for_scan_returns_only_referenced_evidence(store):
    sid = store.create_scan("example.com")
    used = Evidence.create("dns", "DNS A x", "1.2.3.4")
    unused = Evidence.create("dns", "DNS A y", "5.6.7.8")
    store.add_evidence(used)
    store.add_evidence(unused)
    store.add_edge(sid, "domain:x", "resolves_to", "ip:1.2.3.4", [used.id])
    assert [e.id for e in store.evidence_for_scan(sid)] == [used.id]


def test_scans_are_isolated(store):
    s1, s2 = store.create_scan("a.com"), store.create_scan("b.com")
    store.upsert_entity(s1, dom("a.com"), ScopeState.IN)
    assert store.entities(s2) == []


def test_audit_chain_verifies_and_detects_tampering(store):
    sid = store.create_scan("example.com")
    store.append_audit(sid, {"event": "ok", "n": 1})
    store.append_audit(sid, {"event": "ok", "n": 2})
    assert store.verify_audit(sid) is True
    assert [r["n"] for r in store.audit_log(sid)] == [1, 2]
    store._db.execute("UPDATE audit SET record = ? WHERE seq = 1", ('{"event": "forged"}',))
    assert store.verify_audit(sid) is False


def test_store_persists_to_disk(tmp_path):
    path = tmp_path / "s.db"
    first = Store(path)
    sid = first.create_scan("x.com")
    first.upsert_entity(sid, dom("x.com"), ScopeState.IN)
    first.close()
    second = Store(path)
    assert len(second.entities(sid)) == 1
    second.close()
