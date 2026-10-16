import json

import respx
from dnsfakes import StatusResolver
from packfix import provider, write_pack
from test_e2e import mock_internet

from scrutator.model import Entity, EntityType, Evidence, ScopeState
from scrutator.modules.base import ModuleContext
from scrutator.packs import PackSet, load_packs
from scrutator.report import build_report, render_json
from scrutator.scan import run_scan
from scrutator.scope import ScopePolicy
from scrutator.store import Store


def dom(value):
    return Entity(type=EntityType.DOMAIN, value=value)


def make_store():
    store = Store(":memory:")
    sid = store.create_scan("example.com")
    for value in ("example.com", "ghost.example.com"):
        store.upsert_entity(sid, dom(value), ScopeState.IN)
    crt = Evidence.create("crtsh", "GET https://crt.sh/?q=%25.example.com&output=json", "[]")
    nx = Evidence.create("dns", "DNS A ghost.example.com", "NXDOMAIN")
    store.add_evidence(crt)
    store.add_evidence(nx)
    store.add_edge(sid, "domain:example.com", "has_subdomain", "domain:ghost.example.com", [crt.id])
    store.add_scan_evidence(sid, nx.id)  # a fact: it has no relation of its own
    store.set_meta(sid, "scope", json.dumps({"domains": ["example.com"], "cidrs": [], "asns": []}))
    return store, sid, crt, nx


def test_the_report_carries_risks_dependencies_and_the_packs_that_produced_them():
    store, sid, crt, nx = make_store()
    report = build_report(store, sid)
    assert [r["rule_id"] for r in report["risks"]] == ["ghost-hostname"]
    assert report["risks"][0]["evidence_ids"] == [crt.id, nx.id]
    assert nx.id in report["evidence"]  # facts are part of the report's evidence
    assert report["summary"]["risks"] == 1
    assert report["dependencies"] == []
    assert PackSet.from_dict(report["packs"]).effective_sha256 == load_packs().effective_sha256
    assert json.loads(render_json(report)) == report


def test_the_packs_recorded_with_the_scan_are_the_ones_the_report_uses(tmp_path):
    store, sid, *_ = make_store()
    write_pack(tmp_path / "mine", "p.yaml", "providers", [provider()])
    custom = load_packs([tmp_path / "mine"])
    store.set_meta(sid, "packs", json.dumps(custom.to_dict(), sort_keys=True))
    assert build_report(store, sid)["packs"]["effective_sha256"] == custom.effective_sha256
    # an explicit choice wins, for re-evaluating an old scan with newer knowledge
    assert build_report(store, sid, packs=load_packs())["packs"]["effective_sha256"] == load_packs().effective_sha256


async def test_run_scan_records_the_packs_it_was_given(tmp_path, http):
    write_pack(tmp_path / "mine", "p.yaml", "providers", [provider()])
    custom = load_packs([tmp_path / "mine"])
    seed = Entity(type=EntityType.DOMAIN, value="example.com")
    for packs, expected in ((None, load_packs()), (custom, custom)):
        store = Store(":memory:")
        ctx = ModuleContext(http=http, resolver=StatusResolver({("example.com", "A"): ["192.0.2.1"]}))
        with respx.mock(assert_all_called=False) as router:
            mock_internet(router)
            scan_id, _ = await run_scan(seed, ScopePolicy(domains=["example.com"]), store, ctx, packs=packs)
        recorded = PackSet.from_dict(json.loads(store.get_meta(scan_id, "packs")))
        assert recorded.effective_sha256 == expected.effective_sha256
        assert build_report(store, scan_id)["packs"]["effective_sha256"] == expected.effective_sha256
