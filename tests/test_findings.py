from scrutator.findings import build_findings
from scrutator.model import Confidence, Entity, EntityType, Evidence, ScopeState
from scrutator.store import Store


def seed_store():
    store = Store(":memory:")
    sid = store.create_scan("example.com")
    root = Entity(type=EntityType.DOMAIN, value="example.com")
    www = Entity(type=EntityType.DOMAIN, value="www.example.com")
    ip = Entity(type=EntityType.IP, value="93.184.216.34")
    for e in (root, www, ip):
        store.upsert_entity(sid, e, ScopeState.IN)
    return store, sid, root, www, ip


def add(store, sid, src, rel, dst, source, payload):
    ev = Evidence.create(source, f"req {source}", payload)
    store.add_evidence(ev)
    store.add_edge(sid, src.id, rel, dst.id, [ev.id])
    return ev


def test_confidence_follows_number_of_distinct_sources():
    store, sid, root, www, ip = seed_store()
    add(store, sid, www, "resolves_to", ip, "dns", "93.184.216.34")
    add(store, sid, root, "has_subdomain", www, "crtsh", "c1")
    add(store, sid, root, "has_subdomain", www, "wayback", "w1")

    findings = {f.claim: f for f in build_findings(store, sid)}
    assert findings["www.example.com resolves to 93.184.216.34"].confidence is Confidence.LOW
    sub = findings["example.com has subdomain www.example.com"]
    assert sub.confidence is Confidence.MEDIUM
    assert len(sub.evidence_ids) == 2

    add(store, sid, root, "has_subdomain", www, "commoncrawl", "c2")
    findings = {f.claim: f for f in build_findings(store, sid)}
    assert findings["example.com has subdomain www.example.com"].confidence is Confidence.HIGH


def test_two_evidence_records_from_one_source_do_not_corroborate():
    store, sid, root, www, ip = seed_store()
    add(store, sid, root, "has_subdomain", www, "crtsh", "first")
    add(store, sid, root, "has_subdomain", www, "crtsh", "second")
    (finding,) = build_findings(store, sid)
    assert finding.confidence is Confidence.LOW
    assert len(finding.evidence_ids) == 2


def test_every_finding_cites_existing_evidence():
    store, sid, root, www, ip = seed_store()
    add(store, sid, www, "cname_to", ip, "dns", "x")
    for finding in build_findings(store, sid):
        assert finding.evidence_ids
        assert all(store.get_evidence(i) is not None for i in finding.evidence_ids)


def test_unknown_relation_gets_a_readable_claim():
    store, sid, root, www, ip = seed_store()
    add(store, sid, root, "some_new_rel", www, "dns", "x")
    (finding,) = build_findings(store, sid)
    assert finding.claim == "example.com some new rel www.example.com"
