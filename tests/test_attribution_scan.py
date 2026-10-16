import json

import pytest
import respx
from attrscan import MODULES, SEED, resolver, scan, sources, states

from scrutator.attribution.candidates import SELECT_AT, attribute_scan
from scrutator.engine import Engine
from scrutator.model import ScopeState
from scrutator.modules.base import ModuleContext
from scrutator.packs import load_packs
from scrutator.report.build import core_report, promotions
from scrutator.scan import run_scan
from scrutator.scope import ScopePolicy
from scrutator.store import Store


async def test_a_scan_without_attribution_never_touches_a_name_outside_the_scope(http):
    run = await scan(http)
    assert "partner.test" not in {name for name, _ in run.dns.calls}
    assert states(run)["partner.test"] is ScopeState.OUT
    assert not any(s is ScopeState.CANDIDATE for s in states(run).values())
    # the report still explains what it saw, from the certificates alone
    found = {c["entity_id"]: c for c in run.report["attribution"]["candidates"]}
    assert found["domain:partner.test"]["band"] == "possible" and found["domain:partner.test"]["state"] == "out"


async def test_attribution_marks_candidates_and_looks_at_them_passively_once(http):
    run = await scan(http, attribution=True)
    found = {c["entity_id"]: c for c in run.report["attribution"]["candidates"]}
    partner = found["domain:partner.test"]
    assert partner["band"] == "confirmed" and partner["state"] == "candidate"
    assert {s["kind"] for s in partner["signals"]} == {"cert_san", "ns_in_scope", "network_owner"}
    assert run.report["summary"]["candidates"] >= 1 and run.report["summary"]["by_scope"]["candidate"] >= 1

    state = states(run)
    assert state["partner.test"] is ScopeState.CANDIDATE and state["_spf.vendor2.test"] is ScopeState.CANDIDATE
    assert state["ns9.partner-dns.test"] is ScopeState.OUT  # found through a candidate: recorded, never followed
    assert state["198.51.100.7"] is ScopeState.LINKED  # so that the network lookups can follow
    assert state["vendor.test"] is ScopeState.OUT and state["t0.test"] is ScopeState.OUT  # one weak certificate is not enough
    assert 0 < found["domain:vendor.test"]["score"] < SELECT_AT


async def test_nothing_is_queried_that_the_scope_and_the_selected_candidates_do_not_cover(http):
    run = await scan(http, attribution=True)
    queried = {name for name, _ in run.dns.calls}
    scope = ScopePolicy(domains=["example.com"])
    selected = {"partner.test", "_dmarc.partner.test", "_spf.vendor2.test", "_dmarc._spf.vendor2.test"}
    assert queried and all(scope.decide(n).allowed or n in selected for n in queried), sorted(n for n in queried if not scope.decide(n).allowed and n not in selected)
    for never in ("decoy.test", "ns9.partner-dns.test", "vendor.test", "t0.test"):
        assert never not in queried
    crt = {value for kind, value in run.http_log if kind == "crt"}
    assert {"%.partner.test", "%.example.com"} <= crt and not any("vendor.test" == v.removeprefix("%.") or "t0" in v for v in crt)
    rdap = {value for kind, value in run.http_log if kind == "rdap"}
    assert "partner.test" in rdap and rdap.isdisjoint({"decoy.test", "vendor.test", "ns9.partner-dns.test"})
    assert ("asn", "198.51.100.7") in run.http_log


async def test_the_number_of_candidates_looked_at_is_capped_strongest_first(http):
    run = await scan(http, attribution=True, max_candidates=1)
    state = states(run)
    assert state["partner.test"] is ScopeState.CANDIDATE and state["_spf.vendor2.test"] is ScopeState.OUT
    assert json.loads(run.store.get_meta(run.scan_id, "attribution"))["selected"] == ["domain:partner.test"]
    none = await scan(http, attribution=True, max_candidates=0)
    assert not any(s is ScopeState.CANDIDATE for s in states(none).values())


async def test_a_second_pass_changes_nothing_and_queries_nothing_more(http):
    store, dns, log = Store(":memory:"), resolver(), []
    ctx = ModuleContext(http=http, resolver=dns)
    packs = load_packs()
    with respx.mock(assert_all_called=False) as router:
        sources(router, log)
        scan_id, _ = await run_scan(SEED, ScopePolicy(domains=["example.com"]), store, ctx, modules=MODULES, packs=packs, attribution=True)
        calls, requests, audit = len(dns.calls), len(log), len(store.audit_log(scan_id))
        engine = Engine(store, ScopePolicy(domains=["example.com"]), ctx)
        again = await attribute_scan(engine, scan_id, MODULES, packs)
    assert again and len(dns.calls) == calls and len(log) == requests and len(store.audit_log(scan_id)) == audit


async def test_a_candidate_is_audited_with_the_score_that_got_it_selected(http):
    run = await scan(http, attribution=True)
    marks = [r for r in run.store.audit_log(run.scan_id) if r["event"] == "candidate"]
    assert {r["entity"] for r in marks} == {"domain:partner.test", "domain:_spf.vendor2.test"}
    partner = next(r for r in marks if r["entity"] == "domain:partner.test")
    assert partner["score"] == 0.6 and partner["band"] == "possible"
    assert run.store.verify_audit(run.scan_id)


async def test_the_core_report_is_what_the_full_report_is_built_on(http):
    run = await scan(http, attribution=True)
    core = core_report(run.store, run.scan_id)
    for key in ("scope", "entities", "edges", "evidence"):
        assert core[key] == run.report[key]


def test_promotions_are_read_from_the_audit_log_in_order():
    records = [
        {"event": "ok", "module": "dns", "entity": "domain:example.com"},
        {"event": "promoted", "entity": "domain:a.test", "score": 0.9, "band": "probable", "evidence_ids": ["e1"], "via": "cli", "at": "2026-10-17T10:00:00+00:00", "scope_file": "scope.yaml", "extra": "dropped"},
        {"event": "promoted", "entity": "domain:b.test"},
    ]
    found = promotions(records)
    assert [p["entity"] for p in found] == ["domain:a.test", "domain:b.test"]
    assert found[0] == {"entity": "domain:a.test", "score": 0.9, "band": "probable", "evidence_ids": ["e1"], "via": "cli", "at": "2026-10-17T10:00:00+00:00", "scope_file": "scope.yaml"}
    assert found[1]["score"] is None and promotions([]) == []


@pytest.mark.parametrize("flag", [False, True])
async def test_the_audit_chain_survives_attribution(http, flag):
    run = await scan(http, attribution=flag)
    assert run.store.verify_audit(run.scan_id)
