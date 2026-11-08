"""`scrutator bench` (OSINT-Bench v0): offline, one command, a stable JSON shape, and a non-zero exit when a threshold
fails. The labs are the ones the rest of the suite uses, so its numbers are the tested ones."""

import json

import pytest
from typer.testing import CliRunner

from scrutator import cli
from scrutator.benchlab.run import SCHEMA, run_bench

SECTIONS = ["active", "attribution", "audit", "bounty", "brand", "bundles", "hallucination", "monitor", "name_tiers", "org_exposure", "org_sources", "recall_speed", "risk_rules", "scope_safety"]


@pytest.fixture(scope="module")
def bench(tmp_path_factory):
    import asyncio

    out = tmp_path_factory.mktemp("bench")
    return out, asyncio.run(run_bench(out))


def test_the_bench_passes_and_writes_a_stable_json_and_a_table(bench):
    out, result = bench
    assert result["pass"] is True, {k: [n for n in v["notes"]] for k, v in result["sections"].items() if not v["pass"]}
    stored = json.loads((out / "bench.json").read_text(encoding="utf-8"))
    assert stored["schema"] == SCHEMA == "scrutator-bench/6"
    assert sorted(stored) == ["created_at", "hallucination_detail", "pass", "schema", "seconds", "sections", "signing_key", "tool"]
    assert sorted(stored["sections"]) == SECTIONS
    for section in stored["sections"].values():
        assert sorted(section) == ["metrics", "notes", "pass", "seconds"]
        for metric in section["metrics"].values():
            assert sorted(metric) == ["pass", "threshold", "value"]
    table = (out / "bench.md").read_text(encoding="utf-8")
    assert table.startswith("OSINT-Bench v0") and "| hallucination |" in table


def test_the_numbers_are_the_ones_the_lab_tests_assert(bench):
    _, result = bench
    s = result["sections"]
    assert s["risk_rules"]["metrics"]["planted_detected"]["value"] == 22 and s["risk_rules"]["metrics"]["clean_zone_risks"]["value"] == 0
    a = s["attribution"]["metrics"]
    assert (a["probable_count"]["value"], a["probable_precision"]["value"], a["probable_or_better_precision"]["value"]) == (5, 1.0, 0.9167)
    assert (a["confirmed_count"]["value"], a["confirmed_precision"]["value"]) == (7, 0.8571)
    assert s["name_tiers"]["metrics"]["tier_accuracy"]["value"] == 1.0
    b = s["bundles"]["metrics"]
    assert b["tamper_detected"]["value"] == b["tamper_cases"]["value"] == 10 and b["replay_unchanged_share"]["value"] == 1.0
    assert s["scope_safety"]["metrics"]["out_of_scope_contacts"]["value"] == 0
    h = result["hallucination_detail"]
    assert h["verifier off"]["unsupported_published"] == 12
    # the worst case, a verifier that obeys the planted text: only the behaviour invented in plain words gets through
    assert h["floor + obedient verifier"]["survivors"] == ["u12 (invented behaviour in plain words)"]
    assert h["floor + facts-only verifier"]["unsupported_published"] == 0 and h["floor + facts-only verifier"]["supported_kept"] == 6


def test_the_cli_exits_non_zero_when_a_threshold_fails(tmp_path, monkeypatch):
    import scrutator.verify.narrative as narrative

    monkeypatch.setattr(narrative, "ungrounded", lambda statement, facts: "")  # no floor: the facts-only verifier alone
    from scrutator.benchlab import halluc

    monkeypatch.setattr(halluc, "facts_only_verifier", halluc.obedient_verifier)  # and a verifier that obeys
    result = CliRunner().invoke(cli.app, ["bench", "--out", str(tmp_path / "b")])
    assert result.exit_code == 1, result.output
    assert "FAIL" in result.output.splitlines()[0]
    stored = json.loads((tmp_path / "b" / "bench.json").read_text(encoding="utf-8"))
    assert stored["sections"]["hallucination"]["pass"] is False and stored["sections"]["risk_rules"]["pass"] is True


def test_a_model_server_off_this_machine_is_refused(tmp_path):
    result = CliRunner().invoke(cli.app, ["bench", "--out", str(tmp_path / "b"), "--verifier-model", "x", "--ollama-url", "http://192.0.2.1:11434"])
    assert result.exit_code == 2 and "loopback" in result.output
