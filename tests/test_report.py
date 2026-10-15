import json
import re

from scrutator.model import Entity, EntityType, Evidence, ScopeState
from scrutator.report import build_report, render_html, render_json
from scrutator.store import Store

HOSTILE = "</script><script>alert(1)</script><!--"


def make_store():
    store = Store(":memory:")
    sid = store.create_scan("example.com")
    root = Entity(type=EntityType.DOMAIN, value="example.com")
    www = Entity(type=EntityType.DOMAIN, value="www.example.com")
    other = Entity(type=EntityType.DOMAIN, value="cdn.other.net")
    ip = Entity(type=EntityType.IP, value="93.184.216.34")
    store.upsert_entity(sid, root, ScopeState.IN)
    store.upsert_entity(sid, www, ScopeState.IN)
    store.upsert_entity(sid, other, ScopeState.OUT)
    store.upsert_entity(sid, ip, ScopeState.LINKED)
    ev1 = Evidence.create("crtsh", "GET https://crt.sh/", HOSTILE)
    ev2 = Evidence.create("dns", "DNS A www.example.com", "93.184.216.34")
    for ev in (ev1, ev2):
        store.add_evidence(ev)
    store.add_edge(sid, root.id, "has_subdomain", www.id, [ev1.id])
    store.add_edge(sid, www.id, "resolves_to", ip.id, [ev2.id])
    store.add_edge(sid, www.id, "cname_to", other.id, [ev2.id])
    return store, sid, ev1, ev2


def test_report_structure_and_summary():
    store, sid, ev1, ev2 = make_store()
    report = build_report(store, sid, generated_at="2026-10-15T00:00:00+00:00")
    assert report["scan"]["seed"] == "example.com"
    assert report["generated_at"] == "2026-10-15T00:00:00+00:00"
    assert report["summary"]["entities"] == 4
    assert report["summary"]["by_scope"] == {"in": 2, "linked": 1, "out": 1}
    assert report["summary"]["by_type"] == {"domain": 3, "ip": 1}
    assert report["summary"]["edges"] == 3
    assert report["summary"]["findings"] == 3
    assert set(report["evidence"]) == {ev1.id, ev2.id}
    for finding in report["findings"]:
        assert all(i in report["evidence"] for i in finding["evidence_ids"])


def test_json_roundtrip():
    store, sid, *_ = make_store()
    report = build_report(store, sid)
    assert json.loads(render_json(report)) == report


def test_html_neutralises_hostile_evidence():
    store, sid, ev1, _ = make_store()
    html = render_html(build_report(store, sid))
    assert "<script>alert(1)" not in html
    assert html.count("<script") == 2
    assert html.count("</script>") == 2
    data = re.search(r'<script type="application/json" id="data">(.*?)</script>', html, re.S).group(1)
    assert json.loads(data)["evidence"][ev1.id]["payload"] == HOSTILE


def test_html_is_self_contained():
    store, sid, *_ = make_store()
    html = render_html(build_report(store, sid))
    assert html.startswith("<!doctype html>")
    page = re.sub(r'<script type="application/json" id="data">.*?</script>', "", html, flags=re.S)
    assert "http://" not in page.replace("http://www.w3.org/2000/svg", "")
    assert "https://" not in page
