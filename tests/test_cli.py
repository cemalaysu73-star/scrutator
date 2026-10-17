import json
from contextlib import asynccontextmanager

import pytest
from llmfakes import ScriptedProvider
from typer.testing import CliRunner

from scrutator import cli
from scrutator.agent.runner import AgentStats
from scrutator.ai.config import AIMode
from scrutator.ai.runtime import AIRuntime
from scrutator.model import ScopeState
from scrutator.verify.narrative import SummaryResult

runner = CliRunner()


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    """No test may reach a real model server or the network."""

    @asynccontextmanager
    async def fake_context():
        yield None

    async def no_ai(*args, **kwargs):
        return None, AIMode.OFF

    monkeypatch.setattr(cli, "open_context", fake_context)
    monkeypatch.setattr(cli, "ai_client", fake_context)
    monkeypatch.setattr(cli, "build_runtime", no_ai)

    async def fake_run_scan(seed, scope, store, ctx, **kwargs):
        scan_id = store.create_scan(seed.value)
        store.upsert_entity(scan_id, seed, ScopeState.IN)
        return scan_id, AgentStats(rounds=1, modules_run=1, entities=1)

    monkeypatch.setattr(cli, "run_scan", fake_run_scan)


def test_help_lists_commands():
    result = runner.invoke(cli.app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output and "ai" in result.output


def test_invalid_seed_exits_with_code_2():
    result = runner.invoke(cli.app, ["scan", "https://example.com/path"])
    assert result.exit_code == 2
    assert "error" in result.output.lower()


def test_unknown_format_and_unknown_ai_mode_exit_with_code_2(tmp_path):
    assert runner.invoke(cli.app, ["scan", "example.com", "--out", str(tmp_path), "--format", "pdf"]).exit_code == 2
    assert runner.invoke(cli.app, ["scan", "example.com", "--out", str(tmp_path), "--ai", "turbo"]).exit_code == 2


def test_scan_writes_reports_and_database(tmp_path):
    out = tmp_path / "out"
    result = runner.invoke(cli.app, ["scan", "Example.COM", "--out", str(out)])
    assert result.exit_code == 0, result.output
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["scan"]["seed"] == "example.com"
    assert report["ai"] is None
    assert "AI: off" in result.output
    assert (out / "report.html").read_text(encoding="utf-8").startswith("<!doctype html>")
    assert (out / "scrutator.db").exists()


def test_scope_file_is_used(tmp_path, monkeypatch):
    captured = {}

    async def spy(seed, scope, store, ctx, **kwargs):
        captured["allowed"] = scope.decide("api.example.com").allowed
        captured["other"] = scope.decide("example.org").allowed
        captured["max_steps"] = kwargs["max_steps"]
        return store.create_scan(seed.value), AgentStats()

    monkeypatch.setattr(cli, "run_scan", spy)
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text("domains:\n  - example.com\n")
    result = runner.invoke(
        cli.app,
        ["scan", "example.com", "--scope", str(scope_file), "--out", str(tmp_path / "o"), "--format", "json", "--max-steps", "7"],
    )
    assert result.exit_code == 0, result.output
    assert captured == {"allowed": True, "other": False, "max_steps": 7}
    assert not (tmp_path / "o" / "report.html").exists()


def test_scan_with_ai_adds_a_verified_summary_to_the_report(tmp_path, monkeypatch):
    ai = AIRuntime({"planner": ScriptedProvider([], model="qwen3:8b")})

    async def local_ai(*args, **kwargs):
        return ai, AIMode.LOCAL

    async def fake_summarise(runtime, store, scan_id):
        store.add_statement(scan_id, text="Fine.", evidence_ids=[], status="verified", confidence="low")
        return SummaryResult()

    monkeypatch.setattr(cli, "build_runtime", local_ai)
    monkeypatch.setattr(cli, "summarise", fake_summarise)
    out = tmp_path / "out"
    result = runner.invoke(cli.app, ["scan", "example.com", "--out", str(out)])
    assert result.exit_code == 0, result.output
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["ai"]["mode"] == "local"
    assert report["ai"]["providers"]["planner"]["model"] == "qwen3:8b"
    assert [s["text"] for s in report["summary_statements"]] == ["Fine."]
    assert "AI: local" in result.output


def test_no_summary_flag_skips_the_writer(tmp_path, monkeypatch):
    ai = AIRuntime({"planner": ScriptedProvider([])})
    called = []

    async def local_ai(*args, **kwargs):
        return ai, AIMode.LOCAL

    async def fake_summarise(*args):
        called.append(1)
        return SummaryResult()

    monkeypatch.setattr(cli, "build_runtime", local_ai)
    monkeypatch.setattr(cli, "summarise", fake_summarise)
    runner.invoke(cli.app, ["scan", "example.com", "--out", str(tmp_path / "o"), "--no-summary"])
    assert called == []


CLOUD_CONFIG = '[ai]\nmode = "cloud"\n[ai.planner]\nprovider = "anthropic"\nmodel = "claude-x"\napi_key_env = "K"\n'


def test_cloud_endpoints_need_consent(tmp_path):
    config = tmp_path / "c.toml"
    config.write_text(CLOUD_CONFIG)
    args = ["scan", "example.com", "--out", str(tmp_path / "o"), "--config", str(config)]
    declined = runner.invoke(cli.app, args, input="n\n")
    assert declined.exit_code == 2
    assert "api.anthropic.com" in declined.output
    accepted = runner.invoke(cli.app, args, input="y\n")
    assert accepted.exit_code == 0, accepted.output
    flagged = runner.invoke(cli.app, [*args, "--yes-cloud"])
    assert flagged.exit_code == 0 and "Send this data?" not in flagged.output


def test_bad_config_exits_with_code_2(tmp_path):
    config = tmp_path / "c.toml"
    config.write_text('[ai]\nmode = "turbo"\n')
    result = runner.invoke(cli.app, ["scan", "example.com", "--out", str(tmp_path / "o"), "--config", str(config)])
    assert result.exit_code == 2


def doctor_runtime(good):
    def respond(system, user, schema):
        title = schema["title"]
        if title == "Answer":
            return {"answer": 7 if good else 1}
        if title == "Ranking":
            return {"choices": [2 if good else 0], "hypothesis": ""}
        if title == "Entailment":
            return {"supported": "192.0.2.10" in user.split("Evidence:")[0] and good, "reason": ""}
        return {"statements": [{"text": "x", "finding_refs": ["F1"]}]}

    return AIRuntime({role: ScriptedProvider(responder=respond) for role in ("planner", "verifier", "writer")})


def test_ai_doctor_reports_pass_and_fail(monkeypatch):
    async def good(*args, **kwargs):
        return doctor_runtime(True), AIMode.LOCAL

    monkeypatch.setattr(cli, "build_runtime", good)
    ok = runner.invoke(cli.app, ["ai", "doctor"])
    assert ok.exit_code == 0 and "planner: PASS" in ok.output

    async def bad(*args, **kwargs):
        return doctor_runtime(False), AIMode.LOCAL

    monkeypatch.setattr(cli, "build_runtime", bad)
    failed = runner.invoke(cli.app, ["ai", "doctor"])
    assert failed.exit_code == 1 and "FAIL" in failed.output


def test_ai_doctor_without_a_runtime_explains_itself():
    result = runner.invoke(cli.app, ["ai", "doctor"])
    assert result.exit_code == 1
    assert "no AI" in result.output


def test_deadline_and_breaker_flags_reach_the_scan(tmp_path, monkeypatch):
    captured = {}

    async def spy(seed, scope, store, ctx, **kwargs):
        captured["deadline"] = kwargs["deadline"].seconds if kwargs["deadline"] else None
        captured["breaker"] = kwargs["breaker_threshold"]
        return store.create_scan(seed.value), AgentStats()

    monkeypatch.setattr(cli, "run_scan", spy)
    out = str(tmp_path / "o")
    result = runner.invoke(cli.app, ["scan", "example.com", "--out", out, "--deadline", "42", "--breaker", "5"])
    assert result.exit_code == 0, result.output
    assert captured == {"deadline": 42.0, "breaker": 5}
    runner.invoke(cli.app, ["scan", "example.com", "--out", out])
    assert captured == {"deadline": 600.0, "breaker": 3}  # the defaults
    runner.invoke(cli.app, ["scan", "example.com", "--out", out, "--deadline", "0"])
    assert captured["deadline"] is None  # 0 means no deadline


def test_a_scan_cut_short_by_the_deadline_says_so_and_still_writes_the_report(tmp_path, monkeypatch):
    async def cut_short(seed, scope, store, ctx, **kwargs):
        scan_id = store.create_scan(seed.value)
        store.upsert_entity(scan_id, seed, ScopeState.IN)
        store.append_audit(scan_id, {"event": "deadline", "seconds": 5})
        store.append_audit(scan_id, {"event": "breaker", "module": "commoncrawl", "entity": "domain:example.com", "after": 3, "last_error": "x", "group": "commoncrawl"})
        return scan_id, AgentStats(deadline_hit=True)

    monkeypatch.setattr(cli, "run_scan", cut_short)
    out = tmp_path / "o"
    result = runner.invoke(cli.app, ["scan", "example.com", "--out", str(out), "--deadline", "5"])
    assert result.exit_code == 0, result.output
    assert "deadline" in result.output.lower() and "partial" in result.output.lower()
    assert "commoncrawl" in result.output and "marked down" in result.output
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["coverage"] == {"deadline_s": None, "deadline_hit": True, "sources_down": ["commoncrawl"]}


def test_ctrl_c_still_writes_a_report_of_what_was_collected(tmp_path, monkeypatch):
    async def interrupted(seed, scope, store, ctx, **kwargs):
        scan_id = store.create_scan(seed.value)
        store.upsert_entity(scan_id, seed, ScopeState.IN)
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "run_scan", interrupted)
    out = tmp_path / "o"
    result = runner.invoke(cli.app, ["scan", "example.com", "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert "interrupted" in result.output.lower()
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["scan"]["seed"] == "example.com" and report["coverage"]["deadline_hit"] is False
    assert any(r["event"] == "interrupted" for r in __import__("scrutator.store", fromlist=["Store"]).Store(out / "scrutator.db").audit_log(1))
