import json
from contextlib import asynccontextmanager

from typer.testing import CliRunner

from scrutator import cli
from scrutator.expand import ExpandStats
from scrutator.model import ScopeState

runner = CliRunner()


def test_help_lists_scan_command():
    result = runner.invoke(cli.app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output


def test_invalid_seed_exits_with_code_2():
    result = runner.invoke(cli.app, ["scan", "https://example.com/path"])
    assert result.exit_code == 2
    assert "error" in result.output.lower()


def test_unknown_format_exits_with_code_2(tmp_path):
    result = runner.invoke(cli.app, ["scan", "example.com", "--out", str(tmp_path), "--format", "pdf"])
    assert result.exit_code == 2


def test_scan_writes_reports_and_database(tmp_path, monkeypatch):
    @asynccontextmanager
    async def fake_context():
        yield None

    async def fake_run_scan(seed, scope, store, ctx, **kwargs):
        scan_id = store.create_scan(seed.value)
        store.upsert_entity(scan_id, seed, ScopeState.IN)
        return scan_id, ExpandStats(rounds=1, modules_run=1, entities=1)

    monkeypatch.setattr(cli, "open_context", fake_context)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)

    out = tmp_path / "out"
    result = runner.invoke(cli.app, ["scan", "Example.COM", "--out", str(out)])
    assert result.exit_code == 0, result.output
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["scan"]["seed"] == "example.com"
    assert (out / "report.html").read_text(encoding="utf-8").startswith("<!doctype html>")
    assert (out / "scrutator.db").exists()


def test_scope_file_is_used(tmp_path, monkeypatch):
    captured = {}

    @asynccontextmanager
    async def fake_context():
        yield None

    async def fake_run_scan(seed, scope, store, ctx, **kwargs):
        captured["allowed"] = scope.decide("api.example.com").allowed
        captured["other"] = scope.decide("example.org").allowed
        scan_id = store.create_scan(seed.value)
        return scan_id, ExpandStats()

    monkeypatch.setattr(cli, "open_context", fake_context)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text("domains:\n  - example.com\n")

    result = runner.invoke(
        cli.app, ["scan", "example.com", "--scope", str(scope_file), "--out", str(tmp_path / "o"), "--format", "json"]
    )
    assert result.exit_code == 0, result.output
    assert captured == {"allowed": True, "other": False}
    assert not (tmp_path / "o" / "report.html").exists()
