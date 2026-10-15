from scrutator.findings import claim_for, confidence_for, findings_from_report
from scrutator.model import Confidence, Entity, EntityType, Evidence, ScopeState
from scrutator.report import build_report
from scrutator.store import Store


def test_helpers():
    assert claim_for("a.com", "resolves_to", "1.2.3.4") == "a.com resolves to 1.2.3.4"
    assert claim_for("a.com", "mystery_rel", "b.com") == "a.com mystery rel b.com"
    assert [confidence_for(n) for n in (1, 2, 3, 9)] == [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH, Confidence.HIGH]


def make_report():
    store = Store(":memory:")
    sid = store.create_scan("example.com")
    root, www = Entity(type=EntityType.DOMAIN, value="example.com"), Entity(type=EntityType.DOMAIN, value="www.example.com")
    for e in (root, www):
        store.upsert_entity(sid, e, ScopeState.IN)
    for source in ("crtsh", "wayback"):
        ev = Evidence.create(source, f"GET https://{source}.test/", "x")
        store.add_evidence(ev)
        store.add_edge(sid, root.id, "has_subdomain", www.id, [ev.id])
    return build_report(store, sid)


def test_findings_can_be_rebuilt_from_a_report_alone():
    report = make_report()
    assert findings_from_report(report) == report["findings"]
    assert report["findings"][0]["confidence"] == "medium"


def test_rebuilding_exposes_tampered_confidence():
    report = make_report()
    report["findings"][0]["confidence"] = "high"
    assert findings_from_report(report) != report["findings"]
