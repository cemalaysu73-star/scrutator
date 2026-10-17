import json
import re

from scrutator.model import Entity, EntityType, Evidence, ScopeState
from scrutator.report import build_report, render_html
from scrutator.store import Store


def make():
    store = Store(":memory:")
    sid = store.create_scan("example.com")
    root = Entity(type=EntityType.DOMAIN, value="example.com")
    www = Entity(type=EntityType.DOMAIN, value="www.example.com")
    for e in (root, www):
        store.upsert_entity(sid, e, ScopeState.IN)
    ev = Evidence.create("crtsh", "GET https://crt.sh/", "[]")
    store.add_evidence(ev)
    store.add_edge(sid, root.id, "has_subdomain", www.id, [ev.id])
    store.append_audit(sid, {"event": "ok", "module": "crtsh", "entity": root.id, "evidence_ids": [ev.id]})
    store.append_audit(sid, {"event": "error", "module": "wayback", "entity": root.id, "error": "ReadTimeout: "})
    store.append_audit(sid, {"event": "error", "module": "wayback", "entity": www.id, "error": "ReadTimeout: "})
    store.append_audit(sid, {"event": "denied", "module": "dns", "entity": "domain:x.other.net", "reason": "entity is not in scope"})
    return store, sid, ev


def test_source_health_summarises_the_audit_log():
    store, sid, _ = make()
    sources = build_report(store, sid)["sources"]
    assert sources["crtsh"] == {"ok": 1, "error": 0, "denied": 0, "skipped": 0, "cancelled": 0, "down": False, "errors": []}
    assert sources["wayback"]["error"] == 2 and sources["wayback"]["errors"] == ["ReadTimeout: "]
    assert sources["dns"]["denied"] == 1


def test_statements_leads_hypotheses_egress_and_ai_info_are_in_the_report():
    store, sid, ev = make()
    store.add_statement(sid, text="A subdomain exists.", evidence_ids=[ev.id], status="verified", confidence="low")
    store.add_statement(sid, text="A secret site exists.", evidence_ids=[], status="rejected", reason="not supported by the evidence")
    hid = store.add_hypothesis(sid, "there may be more")
    store.settle_hypothesis(hid, "refuted", [ev.id])
    store.record_egress(sid, role="writer", provider="anthropic", model="c", host="api.anthropic.com", bytes_sent=10, payload_sha256="a" * 64, redacted=True)
    report = build_report(store, sid, ai_info={"mode": "cloud", "providers": {}})
    assert report["summary_statements"] == [{"text": "A subdomain exists.", "evidence_ids": [ev.id], "confidence": "low"}]
    assert report["unverified_leads"] == [{"text": "A secret site exists.", "reason": "not supported by the evidence"}]
    assert report["hypotheses"][0]["status"] == "refuted"
    assert report["egress"][0]["host"] == "api.anthropic.com"
    assert report["ai"]["mode"] == "cloud"


def test_report_without_ai_has_empty_ai_sections():
    store, sid, _ = make()
    report = build_report(store, sid)
    assert report["summary_statements"] == [] and report["unverified_leads"] == [] and report["ai"] is None


def test_html_renders_the_new_sections_and_still_neutralises_hostile_text():
    store, sid, ev = make()
    hostile = "</script><script>alert(1)</script>"
    store.add_statement(sid, text=hostile, evidence_ids=[ev.id], status="verified", confidence="low")
    html = render_html(build_report(store, sid))
    assert "Source coverage" in html and "Unverified leads" in html and "AI summary" in html
    assert html.count("<script") == 2 and html.count("</script>") == 2
    data = re.search(r'<script type="application/json" id="data">(.*?)</script>', html, re.S).group(1)
    assert json.loads(data)["summary_statements"][0]["text"] == hostile
