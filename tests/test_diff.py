from scrutator.diff import diff_reports, render_diff
from scrutator.model import Entity, EntityType, Evidence, ScopeState
from scrutator.report import build_report
from scrutator.store import Store

D = EntityType.DOMAIN


def dom(value):
    return Entity(type=D, value=value)


def scan(store, entities, edges, sources=("crtsh",)):
    sid = store.create_scan("example.com")
    for entity, state in entities:
        store.upsert_entity(sid, entity, state)
    for src, rel, dst, sources_ in edges:
        ids = []
        for source in sources_:
            ev = Evidence.create(source, f"GET https://{source}.test/{src.value}{dst.value}", "x")
            store.add_evidence(ev)
            ids.append(ev.id)
        store.add_edge(sid, src.id, rel, dst.id, ids)
    return sid


def test_added_removed_and_changed_things_are_reported():
    store = Store(":memory:")
    root, www, old, new = dom("example.com"), dom("www.example.com"), dom("old.example.com"), dom("new.example.com")
    a = scan(store, [(root, ScopeState.IN), (www, ScopeState.OUT), (old, ScopeState.IN)],
             [(root, "has_subdomain", www, ["crtsh"]), (root, "has_subdomain", old, ["crtsh"])])
    b = scan(store, [(root, ScopeState.IN), (www, ScopeState.IN), (new, ScopeState.IN)],
             [(root, "has_subdomain", www, ["crtsh", "wayback"]), (root, "has_subdomain", new, ["crtsh"])])
    store.append_audit(a, {"event": "error", "module": "wayback", "entity": root.id, "error": "ReadTimeout: "})

    diff = diff_reports(build_report(store, a), build_report(store, b))
    assert [e["value"] for e in diff.added_entities] == ["new.example.com"]
    assert [e["value"] for e in diff.removed_entities] == ["old.example.com"]
    assert diff.changed_entities == [{"id": "domain:www.example.com", "value": "www.example.com", "from": "out", "to": "in"}]
    assert [(e["src"], e["dst"]) for e in diff.added_edges] == [("domain:example.com", "domain:new.example.com")]
    assert [(e["src"], e["dst"]) for e in diff.removed_edges] == [("domain:example.com", "domain:old.example.com")]
    assert diff.changed_findings == [
        {"claim": "example.com has subdomain www.example.com", "from": "low", "to": "medium"}
    ]
    assert diff.source_changes == [{"source": "wayback", "from_errors": 1, "to_errors": 0}]
    assert not diff.empty


def test_identical_scans_have_an_empty_diff_and_say_so():
    store = Store(":memory:")
    root, www = dom("example.com"), dom("www.example.com")
    make = lambda: scan(store, [(root, ScopeState.IN), (www, ScopeState.IN)], [(root, "has_subdomain", www, ["crtsh"])])
    diff = diff_reports(build_report(store, make()), build_report(store, make()))
    assert diff.empty
    assert "No changes" in render_diff(diff, "scan 1", "scan 2")


def test_render_and_dict_forms():
    store = Store(":memory:")
    root, new = dom("example.com"), dom("new.example.com")
    a = scan(store, [(root, ScopeState.IN)], [])
    b = scan(store, [(root, ScopeState.IN), (new, ScopeState.IN)], [(root, "has_subdomain", new, ["crtsh"])])
    diff = diff_reports(build_report(store, a), build_report(store, b))
    text = render_diff(diff, "scan 1", "scan 2")
    assert "scan 1 -> scan 2" in text and "+ entity domain new.example.com" in text and "+ relation" in text
    payload = diff.to_dict()
    assert payload["added_entities"][0]["value"] == "new.example.com" and payload["empty"] is False


def test_reports_without_a_sources_section_still_diff():
    store = Store(":memory:")
    root = dom("example.com")
    a = build_report(store, scan(store, [(root, ScopeState.IN)], []))
    del a["sources"]
    b = build_report(store, scan(store, [(root, ScopeState.IN)], []))
    assert diff_reports(a, b).empty
