import json
from contextlib import asynccontextmanager

import httpx
import pytest
import respx
import yaml
from attrscan import MODULES, resolver, scan, sources

from scrutator.bundle.keys import generate_keypair, load_private_key, private_key_path
from scrutator.bundle.writer import create_bundle
from scrutator.mcp_tools import MAX_STEPS, NOTICE, ToolError, ToolSet
from scrutator.model import ScopeState
from scrutator.modules.base import ModuleContext
from scrutator.store import Store


@pytest.fixture
async def db(http, tmp_path):
    path = tmp_path / "scrutator.db"
    run = await scan(http, db=str(path), attribution=True)
    run.store.close()
    return path


@pytest.fixture
def scope_file(tmp_path):
    path = tmp_path / "scope.yaml"
    path.write_text("domains:\n  - example.com\n", encoding="utf-8")
    return path


def audit_len(db):
    store = Store(db)
    try:
        return len(store.audit_log(1)), store.scope_state(1, "domain:partner.test")
    finally:
        store.close()


# reading -----------------------------------------------------------------------------------------------------------------


async def test_list_candidates_orders_by_strength_and_filters_by_band(db):
    tools = ToolSet(db)
    result = tools.list_candidates()
    assert result["notice"] == NOTICE and result["scan"]["seed"] == "example.com"
    assert [c["entity_id"] for c in result["candidates"]][:1] == ["domain:partner.test"]
    partner = result["candidates"][0]
    assert partner["band"] == "confirmed" and partner["state"] == "candidate" and partner["promoted"] is False
    assert "ns_in_scope" in partner["signals"] and "t0.test" not in json.dumps(result)
    assert any(c["entity_id"] == "domain:t0.test" for c in tools.list_candidates(min_band="unlikely")["candidates"])
    assert [c["band"] for c in tools.list_candidates(min_band="confirmed")["candidates"]] == ["confirmed"]
    with pytest.raises(ToolError, match="min_band"):
        tools.list_candidates(min_band="certain")


async def test_attribution_explains_one_name_or_all_of_them(db):
    tools = ToolSet(db)
    one = tools.attribution(entity="Partner.Test")
    (item,) = one["candidates"]
    assert item["entity_id"] == "domain:partner.test" and item["score"] == 0.974
    assert {s["kind"] for s in item["signals"]} == {"cert_san", "ns_in_scope", "network_owner"}
    assert all(s["evidence_ids"] for s in item["signals"]) and item["explanation"].startswith("partner.test scores")
    assert "could_be_wrong_because" in item and one["leads"] == []
    assert len(tools.attribution()["candidates"]) >= 2
    with pytest.raises(ToolError, match="no attribution"):
        tools.attribution(entity="nobody.test")


async def test_risk_lists_what_the_scan_found_with_its_evidence(db):
    result = ToolSet(db).risk()
    assert result["count"] == len(result["risks"]) and result["notice"] == NOTICE
    assert all(r["evidence_ids"] and r["rule_id"] for r in result["risks"])
    assert ToolSet(db).risk(category="analyst")["count"] <= result["count"]
    with pytest.raises(ToolError, match="category"):
        ToolSet(db).risk(category="everything")


async def test_a_missing_database_or_scan_is_an_error_and_not_a_crash(tmp_path, db):
    with pytest.raises(ToolError, match="no database"):
        ToolSet(tmp_path / "missing.db").risk()
    with pytest.raises(ToolError, match="no scan 9"):
        ToolSet(db).risk(scan_id=9)
    empty = tmp_path / "empty.db"
    Store(empty).close()
    with pytest.raises(ToolError, match="no scans"):
        ToolSet(empty).list_candidates()


async def test_verify_bundle_reports_every_check_and_refuses_other_files(db, tmp_path):
    key_dir = tmp_path / "keys"
    generate_keypair(key_dir)
    store = Store(db)
    path = tmp_path / "proof.scrutator"
    create_bundle(store, 1, load_private_key(private_key_path(key_dir)), path)
    store.close()
    tools = ToolSet(db)
    good = tools.verify_bundle(str(path))
    assert good["ok"] is True and {"signature valid", "attribution derivable", "risks derivable"} <= {c["name"] for c in good["checks"]}
    data = path.read_bytes()
    path.write_bytes(data[:-40] + b"X" * 40)
    assert tools.verify_bundle(str(path))["ok"] is False
    for bad in (str(tmp_path / "nothing.scrutator"), str(db), str(tmp_path)):
        with pytest.raises(ToolError, match=r"\.scrutator"):
            tools.verify_bundle(bad)


# promotion ---------------------------------------------------------------------------------------------------------------


async def test_promotion_is_off_unless_the_user_enabled_it(db, scope_file):
    before = audit_len(db)
    for tools in (ToolSet(db), ToolSet(db, allow_promote=True), ToolSet(db, scope_file=scope_file)):
        with pytest.raises(ToolError, match="disabled"):
            tools.promote_candidate("partner.test", confirm=True)
    assert audit_len(db) == before and scope_file.read_text(encoding="utf-8") == "domains:\n  - example.com\n"


async def test_promotion_needs_an_explicit_confirm_and_a_candidate(db, scope_file):
    tools = ToolSet(db, scope_file=scope_file, allow_promote=True)
    before = audit_len(db)
    for confirm in (False, None, "yes", 1):
        with pytest.raises(ToolError, match="confirm=true"):
            tools.promote_candidate("partner.test", confirm=confirm)
    for name in ("t0.test", "www.example.com", "nobody.test"):
        with pytest.raises(ToolError, match="not a candidate|not an entity"):
            tools.promote_candidate(name, confirm=True)
    assert audit_len(db) == before and scope_file.read_text(encoding="utf-8") == "domains:\n  - example.com\n"


async def test_a_confirmed_promotion_edits_the_scope_file_and_the_audit_log(db, scope_file):
    tools = ToolSet(db, scope_file=scope_file, allow_promote=True)
    result = tools.promote_candidate("domain:partner.test", confirm=True)
    assert result["scan_id"] == 1 and result["promoted"]["via"] == "mcp" and result["promoted"]["band"] == "confirmed"
    assert yaml.safe_load(scope_file.read_text(encoding="utf-8"))["domains"] == ["example.com", "partner.test"]
    assert audit_len(db)[1] is ScopeState.IN
    assert tools.list_candidates()["candidates"][0]["promoted"] is True
    with pytest.raises(ToolError, match="not a candidate"):
        tools.promote_candidate("partner.test", confirm=True)  # it is in scope now


# scanning ----------------------------------------------------------------------------------------------------------------


def lab_context(dns):
    @asynccontextmanager
    async def context():
        async with httpx.AsyncClient(follow_redirects=True) as http:
            yield ModuleContext(http=http, resolver=dns)

    return context


async def test_scanning_is_off_unless_the_user_enabled_it(tmp_path, scope_file):
    for tools in (ToolSet(tmp_path / "x.db"), ToolSet(tmp_path / "x.db", allow_scan=True), ToolSet(tmp_path / "x.db", scope_file=scope_file)):
        with pytest.raises(ToolError, match="disabled"):
            await tools.scan("example.com")
    assert not (tmp_path / "x.db").exists()


@pytest.mark.parametrize("seed", ["evil.test", "example.com.evil.test", "203.0.113.9", "partner.test", "not a host!", "https://example.com/x"])
async def test_a_seed_outside_the_scope_is_refused_before_anything_is_looked_up(tmp_path, scope_file, seed):
    dns, log = resolver(), []
    tools = ToolSet(tmp_path / "scans" / "x.db", scope_file=scope_file, allow_scan=True, context=lab_context(dns), modules=MODULES)
    with respx.mock(assert_all_called=False) as router:
        sources(router, log)
        with pytest.raises(ToolError):
            await tools.scan(seed)
    assert dns.calls == [] and log == [] and not (tmp_path / "scans").exists()


async def test_a_scan_inside_the_scope_is_stored_and_summarised(tmp_path, scope_file):
    dns, log = resolver(), []
    path = tmp_path / "scans" / "x.db"
    tools = ToolSet(path, scope_file=scope_file, allow_scan=True, context=lab_context(dns), modules=MODULES)
    with respx.mock(assert_all_called=False) as router:
        sources(router, log)
        result = await tools.scan("Example.COM", max_steps=500)
    assert result["scan_id"] == 1 and result["seed"] == "example.com" and result["notice"] == NOTICE
    assert result["lookups"] <= MAX_STEPS and result["candidates"]["confirmed"] == 1 and set(result["risks"]) == {"high", "medium", "low", "info"}
    assert tools.list_candidates()["candidates"][0]["entity_id"] == "domain:partner.test"  # the scan is in the database the reading tools use
    # the candidates were looked at passively and nothing else outside the scope was queried
    assert {name for name, _ in dns.calls} - {"example.com", "ns1.example.com", "ns2.example.com", "www.example.com", "_dmarc.example.com", "partner.test", "_dmarc.partner.test", "_spf.vendor2.test"} == set()


async def test_the_step_budget_is_clamped(tmp_path, scope_file):
    dns, log = resolver(), []
    tools = ToolSet(tmp_path / "x.db", scope_file=scope_file, allow_scan=True, context=lab_context(dns), modules=MODULES)
    with respx.mock(assert_all_called=False) as router:
        sources(router, log)
        result = await tools.scan("example.com", max_steps=-5, attribution=False)
    assert result["lookups"] == 1 and result["steps_exhausted"] is True and result["candidates"]["confirmed"] == 0
