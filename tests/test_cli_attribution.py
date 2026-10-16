import json
from contextlib import asynccontextmanager

import pytest
import yaml
from attrscan import scan
from llmfakes import ScriptedProvider
from typer.testing import CliRunner

from scrutator import cli
from scrutator.agent.runner import AgentStats
from scrutator.ai.config import AIMode
from scrutator.ai.runtime import AIRuntime
from scrutator.analyst.leads import LeadResult
from scrutator.model import ScopeState
from scrutator.scope import ScopePolicy
from scrutator.store import Store

runner = CliRunner()


@pytest.fixture
async def db(http, tmp_path):
    """A database holding one scan with candidates in it."""
    path = tmp_path / "scrutator.db"
    run = await scan(http, db=str(path), attribution=True)
    run.store.close()
    return path


def invoke(*args):
    return runner.invoke(cli.app, [str(a) for a in args])


async def test_candidates_lists_the_strongest_first_and_says_how_to_go_on(db):
    result = invoke("candidates", "--db", db)
    assert result.exit_code == 0, result.output
    lines = result.output.splitlines()
    assert lines[0].startswith("scan 1 of example.com. Candidates:")
    assert lines[1].startswith("[CONFIRMED") and "domain:partner.test" in lines[1] and "(candidate;" in lines[1]
    assert any("_spf.vendor2.test" in line and "[POSSIBLE " in line for line in lines)
    assert not any("t0.test" in line for line in lines)  # unlikely names are hidden by default
    assert "scrutator promote NAME --scope FILE" in result.output


async def test_candidates_can_be_filtered_and_printed_as_json(db):
    assert "t0.test" in invoke("candidates", "--db", db, "--min-band", "unlikely").output
    only = invoke("candidates", "--db", db, "--min-band", "confirmed")
    assert "partner.test" in only.output and "vendor2" not in only.output
    data = json.loads(invoke("candidates", "--db", db, "--json").output)
    assert [c["entity_id"] for c in data["candidates"]][:1] == ["domain:partner.test"] and data["promotions"] == []
    assert invoke("candidates", "--db", db, "--min-band", "certain").exit_code == 2


async def test_attribution_explains_every_signal_and_what_could_make_it_wrong(db):
    result = invoke("attribution", "--db", db, "--entity", "partner.test")
    assert result.exit_code == 0, result.output
    out = result.output
    assert "[CONFIRMED] domain:partner.test  score 0.97" in out
    assert "+ ns_in_scope 0.90: partner.test is delegated to ns1.example.com" in out and "+ cert_san 0.60" in out
    t0 = invoke("attribution", "--db", db, "--entity", "t0.test").output
    assert "? Only one kind of evidence supports this (cert_san)" in t0 and "- " not in t0.split("\n", 1)[1].split("+")[0]
    assert invoke("attribution", "--db", db, "--entity", "nobody.test").exit_code == 2
    listing = invoke("attribution", "--db", db).output
    assert "partner.test" in listing and "t0.test" not in listing
    assert json.loads(invoke("attribution", "--db", db, "--json").output)["attribution"]["ruleset"] == 1


async def test_promote_asks_first_then_writes_the_scope_file_and_the_audit_log(db, tmp_path):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text("domains:\n  - example.com\n", encoding="utf-8")
    declined = runner.invoke(cli.app, ["promote", "partner.test", "--scope", str(scope_file), "--db", str(db)], input="n\n")
    assert declined.exit_code == 2 and "declined" in declined.output
    assert not ScopePolicy.from_file(scope_file).decide("partner.test").allowed

    accepted = runner.invoke(cli.app, ["promote", "domain:partner.test", "--scope", str(scope_file), "--db", str(db)], input="y\n")
    assert accepted.exit_code == 0, accepted.output
    assert "confirmed (score 0.97)" in accepted.output and "recorded in the audit log" in accepted.output
    assert yaml.safe_load(scope_file.read_text(encoding="utf-8"))["domains"] == ["example.com", "partner.test"]

    store = Store(db)
    try:
        assert store.scope_state(1, "domain:partner.test") is ScopeState.IN
        (promoted,) = [r for r in store.audit_log(1) if r["event"] == "promoted"]
        assert promoted["via"] == "cli" and promoted["scope_file"] == "scope.yaml" and store.verify_audit(1)
    finally:
        store.close()
    assert "(in, promoted;" in invoke("candidates", "--db", db).output


async def test_promote_refuses_anything_that_is_not_a_candidate(db, tmp_path):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text("domains:\n  - example.com\n", encoding="utf-8")
    for name in ("t0.test", "www.example.com", "nobody.test"):
        result = invoke("promote", name, "--scope", scope_file, "--db", db, "--yes")
        assert result.exit_code == 2 and "not a candidate" in result.output, name
    assert scope_file.read_text(encoding="utf-8") == "domains:\n  - example.com\n"
    assert invoke("promote", "partner.test", "--db", db, "--yes").exit_code == 2  # --scope is required
    assert invoke("promote", "partner.test", "--scope", scope_file, "--db", tmp_path / "missing.db", "--yes").exit_code == 2


async def test_a_bundle_can_be_read_without_a_database(db, tmp_path):
    from scrutator.bundle.keys import generate_keypair, load_private_key, private_key_path
    from scrutator.bundle.writer import create_bundle

    key_dir = tmp_path / "keys"
    generate_keypair(key_dir)
    store = Store(db)
    create_bundle(store, 1, load_private_key(private_key_path(key_dir)), tmp_path / "proof.scrutator")
    store.close()
    result = invoke("candidates", tmp_path / "proof.scrutator")
    assert result.exit_code == 0 and "domain:partner.test" in result.output and "proof.scrutator of example.com" in result.output


# the scan command ------------------------------------------------------------------------------------------------


@pytest.fixture
def faked(monkeypatch):
    seen = {}

    @asynccontextmanager
    async def fake_context():
        yield None

    async def no_ai(*args, **kwargs):
        return None, AIMode.OFF

    async def fake_run_scan(seed, scope, store, ctx, **kwargs):
        seen.update(kwargs)
        scan_id = store.create_scan(seed.value)
        store.upsert_entity(scan_id, seed, ScopeState.IN)
        return scan_id, AgentStats(rounds=1, modules_run=1, entities=1)

    monkeypatch.setattr(cli, "open_context", fake_context)
    monkeypatch.setattr(cli, "ai_client", fake_context)
    monkeypatch.setattr(cli, "build_runtime", no_ai)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    return seen, monkeypatch


def test_scan_passes_the_attribution_options_and_reports_the_candidates(tmp_path, faked):
    seen, _ = faked
    result = invoke("scan", "example.com", "--out", tmp_path, "--attribution", "--max-candidates", "3")
    assert result.exit_code == 0, result.output
    assert seen["attribution"] is True and seen["max_candidates"] == 3
    assert "Candidates: 0 (0 confirmed, 0 probable, 0 possible). Run `scrutator candidates` for the list." in result.output
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["attribution"]["candidates"] == [] and report["promotions"] == []


def test_scan_without_the_flag_does_not_attribute_and_stays_quiet_about_it(tmp_path, faked):
    seen, _ = faked
    result = invoke("scan", "example.com", "--out", tmp_path)
    assert result.exit_code == 0 and seen["attribution"] is False and "Candidates:" not in result.output


def test_scan_with_a_model_reports_the_leads(tmp_path, faked):
    _, monkeypatch = faked
    runtime = AIRuntime({"planner": ScriptedProvider(model="p"), "verifier": ScriptedProvider(model="v")})

    async def with_ai(*args, **kwargs):
        return runtime, AIMode.LOCAL

    async def leads(ai, store, scan_id):
        return LeadResult(verified=[{}, {}], rejected=[{}], dropped=4)

    async def no_summary(ai, store, scan_id):
        from scrutator.verify.narrative import SummaryResult

        return SummaryResult(skipped_reason="test")

    monkeypatch.setattr(cli, "build_runtime", with_ai)
    monkeypatch.setattr(cli, "run_leads", leads)
    monkeypatch.setattr(cli, "summarise", no_summary)
    result = invoke("scan", "example.com", "--out", tmp_path, "--attribution")
    assert result.exit_code == 0, result.output
    assert "Leads: 2 verified, 1 rejected, 4 dropped." in result.output
    plain = invoke("scan", "example.com", "--out", tmp_path / "plain")
    assert "Leads:" not in plain.output
