import json

from scrutator.report import build_report
from scrutator.store import Store


def test_scope_and_ai_info_come_from_scan_meta_unless_overridden():
    store = Store(":memory:")
    sid = store.create_scan("example.com")
    assert build_report(store, sid)["scope"] is None
    store.set_meta(sid, "scope", json.dumps({"domains": ["example.com"], "cidrs": [], "asns": []}))
    store.set_meta(sid, "ai", json.dumps({"mode": "local"}))
    report = build_report(store, sid)
    assert report["scope"] == {"domains": ["example.com"], "cidrs": [], "asns": []}
    assert report["ai"] == {"mode": "local"}
    assert build_report(store, sid, ai_info={"mode": "cloud"})["ai"] == {"mode": "cloud"}
