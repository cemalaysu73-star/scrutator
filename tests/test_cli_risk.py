import json
import zipfile
from contextlib import asynccontextmanager

import pytest
from packfix import provider, takeover, write_pack
from riskbundlefix import forge_report, make_risky_store
from typer.testing import CliRunner

from scrutator import cli
from scrutator.agent.runner import AgentStats
from scrutator.ai.config import AIMode
from scrutator.bundle.reader import read_raw
from scrutator.model import ScopeState
from scrutator.packs import PackSet

runner = CliRunner()


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    @asynccontextmanager
    async def fake_context():
        yield None

    async def no_ai(*args, **kwargs):
        return None, AIMode.OFF

    monkeypatch.setattr(cli, "open_context", fake_context)
    monkeypatch.setattr(cli, "ai_client", fake_context)
    monkeypatch.setattr(cli, "build_runtime", no_ai)


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "scans.db"
    store, _ = make_risky_store(path=path)
    store.close()
    return path


def test_risk_lists_the_risks_of_the_latest_scan_with_their_evidence_and_remediation(db):
    result = runner.invoke(cli.app, ["risk", "--db", str(db)])
    assert result.exit_code == 0, result.output
    assert "Risks: 3 (2 high, 0 medium, 0 low, 1 info)." in result.output
    assert "[HIGH  ] dangling-cname-claimable  domain:shop.example.com" in result.output
    assert "evidence: 2 record(s)" in result.output and "fix: Delete the CNAME record" in result.output
    assert "Provider dependencies:" in result.output and "Microsoft Azure" in result.output


def test_risk_json_and_category_filter(db):
    data = json.loads(runner.invoke(cli.app, ["risk", "1", "--db", str(db), "--json"]).output)
    assert [r["rule_id"] for r in data["risks"]] == ["dangling-cname-claimable", "spf-allows-all", "ghost-hostname"]
    analyst = json.loads(runner.invoke(cli.app, ["risk", "--db", str(db), "--json", "--category", "analyst"]).output)
    assert [r["rule_id"] for r in analyst["risks"]] == ["ghost-hostname"]
    assert runner.invoke(cli.app, ["risk", "--db", str(db), "--category", "other"]).exit_code == 2


def test_risk_writes_sarif(db, tmp_path):
    target = tmp_path / "risks.sarif"
    result = runner.invoke(cli.app, ["risk", "--db", str(db), "--sarif", str(target)])
    assert result.exit_code == 0 and f"Wrote {target}" in result.output
    doc = json.loads(target.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0" and len(doc["runs"][0]["results"]) == 3


def test_the_exit_code_policy_is_zero_unless_fail_on_is_met(db):
    assert runner.invoke(cli.app, ["risk", "--db", str(db)]).exit_code == 0
    assert runner.invoke(cli.app, ["risk", "--db", str(db), "--fail-on", "high"]).exit_code == 1
    assert runner.invoke(cli.app, ["risk", "--db", str(db), "--fail-on", "info"]).exit_code == 1
    only_analyst = runner.invoke(cli.app, ["risk", "--db", str(db), "--category", "analyst", "--fail-on", "low"])
    assert only_analyst.exit_code == 0  # the only analyst finding is info
    assert runner.invoke(cli.app, ["risk", "--db", str(db), "--fail-on", "urgent"]).exit_code == 2


def test_usage_errors_exit_with_code_2(tmp_path):
    assert runner.invoke(cli.app, ["risk", "--db", str(tmp_path / "missing.db")]).exit_code == 2
    assert runner.invoke(cli.app, ["risk", "9", "--db", str(tmp_path / "missing.db")]).exit_code == 2


def test_risk_can_re_evaluate_a_scan_with_a_pack_directory(db, tmp_path):
    write_pack(tmp_path / "mine", "t.yaml", "takeover", [takeover("azure-removed", cname=["nowhere.example.net"])])
    plain = json.loads(runner.invoke(cli.app, ["risk", "--db", str(db), "--json"]).output)
    extended = json.loads(runner.invoke(cli.app, ["risk", "--db", str(db), "--json", "--packs", str(tmp_path / "mine")]).output)
    assert plain["risks"] == extended["risks"]  # an unrelated entry changes nothing
    broken = tmp_path / "broken"
    write_pack(broken, "bad.yaml", "providers", [provider("Bad Id")])
    result = runner.invoke(cli.app, ["risk", "--db", str(db), "--packs", str(broken)])
    assert result.exit_code == 2 and "bad.yaml" in result.output


def test_risk_reads_a_verified_bundle_and_refuses_a_forged_one(db, tmp_path):
    key_dir = tmp_path / "keys"
    assert runner.invoke(cli.app, ["keygen", "--key-dir", str(key_dir)]).exit_code == 0
    bundle = tmp_path / "proof.scrutator"
    assert runner.invoke(cli.app, ["export", "--db", str(db), "--bundle", str(bundle), "--key-dir", str(key_dir)]).exit_code == 0
    shown = runner.invoke(cli.app, ["risk", str(bundle)])
    assert shown.exit_code == 0 and "proof.scrutator of example.com. Risks: 3" in shown.output
    assert runner.invoke(cli.app, ["risk", str(bundle), "--packs", str(tmp_path)]).exit_code == 2
    files = read_raw(bundle).files
    files["report.json"] = files["report.json"].replace(b'"severity": "high"', b'"severity": "info"', 1)
    forged = tmp_path / "forged.scrutator"
    with zipfile.ZipFile(forged, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    refused = runner.invoke(cli.app, ["risk", str(forged)])
    assert refused.exit_code == 2 and "verification" in refused.output


def test_packs_list_and_validate():
    listing = runner.invoke(cli.app, ["packs", "list"])
    assert listing.exit_code == 0, listing.output
    assert "providers.yaml" in listing.output and "bundled" in listing.output and "takeover fingerprints" in listing.output
    assert "valid." in runner.invoke(cli.app, ["packs", "validate"]).output


def test_packs_validate_reports_every_problem_and_manifest_writes_the_hashes(tmp_path):
    directory = tmp_path / "mine"
    write_pack(directory, "a.yaml", "providers", [provider("Bad Id")])
    result = runner.invoke(cli.app, ["packs", "validate", str(directory)])
    assert result.exit_code == 1 and "a.yaml" in result.output
    write_pack(directory, "a.yaml", "providers", [provider()])
    made = runner.invoke(cli.app, ["packs", "manifest", str(directory)])
    assert made.exit_code == 0 and "1 file(s)" in made.output
    assert "valid." in runner.invoke(cli.app, ["packs", "validate", str(directory)]).output
    assert runner.invoke(cli.app, ["packs", "manifest", str(tmp_path / "nope")]).exit_code == 2
    listing = runner.invoke(cli.app, ["packs", "list", "--packs", str(directory)])
    assert listing.exit_code == 0 and "user" in listing.output


def test_scan_takes_packs_and_reports_the_risk_count(tmp_path, monkeypatch):
    seen = {}

    async def fake_run_scan(seed, scope, store, ctx, **kwargs):
        seen["packs"] = kwargs["packs"]
        scan_id = store.create_scan(seed.value)
        store.upsert_entity(scan_id, seed, ScopeState.IN)
        return scan_id, AgentStats(rounds=1, modules_run=1, entities=1)

    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    write_pack(tmp_path / "mine", "p.yaml", "providers", [provider()])
    out = tmp_path / "out"
    result = runner.invoke(cli.app, ["scan", "example.com", "--out", str(out), "--packs", str(tmp_path / "mine")])
    assert result.exit_code == 0, result.output
    assert isinstance(seen["packs"], PackSet) and any(e.id == "example-dns" for e in seen["packs"].providers)
    assert "Risks: 0 (0 high, 0 medium, 0 low, 0 info)." in result.output
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["risks"] == [] and "packs" in report
    bad = runner.invoke(cli.app, ["scan", "example.com", "--out", str(out), "--packs", str(tmp_path / "missing")])
    assert bad.exit_code == 2 and "packs" in bad.output


def test_a_bundle_from_before_risk_analysis_is_explained_not_crashed_on(db, tmp_path):
    from scrutator.bundle.keys import load_private_key, private_key_path

    key_dir = tmp_path / "keys"
    runner.invoke(cli.app, ["keygen", "--key-dir", str(key_dir)])
    bundle = tmp_path / "proof.scrutator"
    runner.invoke(cli.app, ["export", "--db", str(db), "--bundle", str(bundle), "--key-dir", str(key_dir)])

    def strip(report):
        for key in ("risks", "dependencies", "packs"):
            del report[key]

    def legacy(manifest):
        del manifest["analysis"]

    old = forge_report(bundle, tmp_path / "old.scrutator", load_private_key(private_key_path(key_dir)), strip, legacy)
    result = runner.invoke(cli.app, ["risk", str(old)])
    assert result.exit_code == 2 and "predates risk analysis" in result.output
