import pytest
import yaml
from attrscan import scan, states

from scrutator.attribution.promote import PromotionError, add_to_scope_file, promote
from scrutator.model import ScopeState
from scrutator.report import build_report
from scrutator.scope import ScopePolicy

NOW = "2026-10-17T09:30:00+00:00"


def scope_file(tmp_path, text="# the engagement scope\ndomains:\n  - example.com\n"):
    path = tmp_path / "scope.yaml"
    path.write_text(text, encoding="utf-8")
    return path


async def test_promoting_a_candidate_writes_the_scope_file_the_audit_log_and_the_state(http, tmp_path):
    run = await scan(http, attribution=True)
    path = scope_file(tmp_path)
    record = promote(run.store, run.scan_id, "domain:partner.test", scope_file=path, via="cli", now=NOW)

    assert ScopePolicy.from_file(path).decide("www.partner.test").allowed
    assert ScopePolicy.from_file(path).decide("example.com").allowed
    assert (tmp_path / "scope.yaml.bak").read_text(encoding="utf-8").startswith("# the engagement scope")
    assert states(run)["partner.test"] is ScopeState.IN

    promoted = [r for r in run.store.audit_log(run.scan_id) if r["event"] == "promoted"]
    assert promoted == [{"event": "promoted", **record}]
    assert record["entity"] == "domain:partner.test" and record["band"] == "confirmed" and record["score"] == 0.974
    assert record["via"] == "cli" and record["at"] == NOW and record["scope_file"] == "scope.yaml"
    assert record["evidence_ids"] and run.store.verify_audit(run.scan_id)


async def test_the_report_lists_the_promotion_and_keeps_explaining_the_attribution(http, tmp_path):
    run = await scan(http, attribution=True)
    promote(run.store, run.scan_id, "domain:partner.test", scope_file=scope_file(tmp_path), via="mcp", now=NOW)
    report = build_report(run.store, run.scan_id)
    assert [(p["entity"], p["via"], p["at"]) for p in report["promotions"]] == [("domain:partner.test", "mcp", NOW)]
    item = next(c for c in report["attribution"]["candidates"] if c["entity_id"] == "domain:partner.test")
    assert item["state"] == "in" and item["band"] == "confirmed"  # the scope recorded with the scan is unchanged


async def test_only_a_candidate_can_be_promoted_and_a_refusal_changes_nothing(http, tmp_path):
    run = await scan(http, attribution=True)
    path = scope_file(tmp_path)
    before = path.read_text(encoding="utf-8")
    audit = len(run.store.audit_log(run.scan_id))
    for entity_id, why in (
        ("domain:t0.test", "out"),  # seen on a certificate, never selected
        ("domain:www.example.com", "in"),
        ("ip:198.51.100.7", "linked"),
        ("domain:nobody.test", "not an entity"),
    ):
        with pytest.raises(PromotionError, match=why):
            promote(run.store, run.scan_id, entity_id, scope_file=path, now=NOW)
    assert path.read_text(encoding="utf-8") == before and not (tmp_path / "scope.yaml.bak").exists()
    assert len(run.store.audit_log(run.scan_id)) == audit and states(run)["t0.test"] is ScopeState.OUT


async def test_a_scope_file_that_cannot_be_written_leaves_the_scan_untouched(http, tmp_path):
    run = await scan(http, attribution=True)
    audit = len(run.store.audit_log(run.scan_id))
    with pytest.raises(PromotionError, match="cannot read"):
        promote(run.store, run.scan_id, "domain:partner.test", scope_file=tmp_path / "missing.yaml", now=NOW)
    bad = scope_file(tmp_path, "domains: [example.com]\nwebsites: [x]\n")
    with pytest.raises(PromotionError, match="not a scope file"):
        promote(run.store, run.scan_id, "domain:partner.test", scope_file=bad, now=NOW)
    assert states(run)["partner.test"] is ScopeState.CANDIDATE and len(run.store.audit_log(run.scan_id)) == audit


def test_adding_a_domain_that_is_already_covered_changes_nothing(tmp_path):
    path = scope_file(tmp_path)
    assert add_to_scope_file(path, "www.example.com") is False
    assert not (tmp_path / "scope.yaml.bak").exists()
    assert add_to_scope_file(path, "partner.test") is True
    assert yaml.safe_load(path.read_text(encoding="utf-8")) == {"domains": ["example.com", "partner.test"]}
    assert add_to_scope_file(path, "partner.test") is False


def test_other_scope_keys_are_kept_and_a_bad_name_is_refused(tmp_path):
    path = scope_file(tmp_path, "domains: [example.com]\ncidrs: ['203.0.113.0/24']\nasns: [64500]\n")
    add_to_scope_file(path, "partner.test")
    assert yaml.safe_load(path.read_text(encoding="utf-8")) == {"domains": ["example.com", "partner.test"], "cidrs": ["203.0.113.0/24"], "asns": [64500]}
    with pytest.raises(PromotionError, match="cannot add"):
        add_to_scope_file(path, "not a host!")
    (tmp_path / "x").mkdir()
    empty = scope_file(tmp_path / "x", "cidrs: ['203.0.113.0/24']\n")
    assert add_to_scope_file(empty, "partner.test") is True
    assert ScopePolicy.from_file(empty).decide("partner.test").allowed
