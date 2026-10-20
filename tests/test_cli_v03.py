import json
import zipfile
from contextlib import asynccontextmanager

import httpx
import pytest
import respx
from typer.testing import CliRunner

from scrutator import cli
from scrutator.agent.runner import AgentStats
from scrutator.ai.config import AIMode
from scrutator.bundle.reader import read_raw
from scrutator.model import Entity, EntityType, ScopeState
from scrutator.store import Store

runner = CliRunner()


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    @asynccontextmanager
    async def fake_context():
        yield None

    async def no_ai(*args, **kwargs):
        return None, AIMode.OFF

    async def instant(seconds):
        pass

    monkeypatch.setattr(cli, "open_context", fake_context)
    monkeypatch.setattr(cli, "ai_client", fake_context)
    monkeypatch.setattr(cli, "build_runtime", no_ai)
    monkeypatch.setattr(cli, "_sleep", instant)


def make_db(tmp_path):
    path = tmp_path / "scans.db"
    store = Store(path)
    sid = store.create_scan("example.com")
    root = Entity(type=EntityType.DOMAIN, value="example.com")
    www = Entity(type=EntityType.DOMAIN, value="www.example.com")
    from scrutator.model import Evidence

    for e in (root, www):
        store.upsert_entity(sid, e, ScopeState.IN)
    ev = Evidence.create("crtsh", "GET https://crt.sh/?q=example.com", "[]")
    store.add_evidence(ev)
    store.add_edge(sid, root.id, "has_subdomain", www.id, [ev.id])
    store.append_audit(sid, {"event": "ok", "module": "crtsh", "entity": root.id, "evidence_ids": [ev.id]})
    store.close()
    return path


def keygen(tmp_path):
    key_dir = tmp_path / "keys"
    result = runner.invoke(cli.app, ["keygen", "--key-dir", str(key_dir)])
    assert result.exit_code == 0, result.output
    return key_dir, result.output


def test_keygen_creates_keys_prints_the_fingerprint_and_refuses_to_overwrite(tmp_path):
    key_dir, output = keygen(tmp_path)
    assert (key_dir / "signing.key").exists() and (key_dir / "signing.pub").exists()
    assert "fingerprint" in output.lower()
    again = runner.invoke(cli.app, ["keygen", "--key-dir", str(key_dir)])
    assert again.exit_code == 2


def test_export_then_verify_passes_and_tampering_fails(tmp_path):
    db = make_db(tmp_path)
    key_dir, output = keygen(tmp_path)
    bundle = tmp_path / "proof.scrutator"
    exported = runner.invoke(cli.app, ["export", "--db", str(db), "--bundle", str(bundle), "--key-dir", str(key_dir)])
    assert exported.exit_code == 0, exported.output

    ok = runner.invoke(cli.app, ["verify", str(bundle)])
    assert ok.exit_code == 0 and "PASS  signature valid" in ok.output and "not pinned" in ok.output

    pub = key_dir / "signing.pub"
    pinned = runner.invoke(cli.app, ["verify", str(bundle), "--pin", str(pub)])
    assert pinned.exit_code == 0 and "not pinned" not in pinned.output and "PASS  signing key pinned" in pinned.output
    wrong = runner.invoke(cli.app, ["verify", str(bundle), "--pin", "0" * 64])
    assert wrong.exit_code == 1 and "FAIL  signing key pinned" in wrong.output

    files = read_raw(bundle).files
    files["report.json"] = files["report.json"].replace(b"example.com", b"exampie.com", 1)
    tampered = tmp_path / "tampered.scrutator"
    with zipfile.ZipFile(tampered, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    bad = runner.invoke(cli.app, ["verify", str(tampered)])
    assert bad.exit_code == 1 and "FAIL  file hashes" in bad.output


def test_export_without_a_key_explains_how_to_make_one(tmp_path):
    db = make_db(tmp_path)
    result = runner.invoke(cli.app, ["export", "--db", str(db), "--bundle", str(tmp_path / "p.scrutator"), "--key-dir", str(tmp_path / "nokeys")])
    assert result.exit_code == 2 and "keygen" in result.output


def test_verify_replay_reports_drift_without_failing(tmp_path, monkeypatch):
    db = make_db(tmp_path)
    key_dir, _ = keygen(tmp_path)
    bundle = tmp_path / "proof.scrutator"
    runner.invoke(cli.app, ["export", "--db", str(db), "--bundle", str(bundle), "--key-dir", str(key_dir)])

    @asynccontextmanager
    async def real_http(**_):  # the replay passes its egress guard; the fake client has none
        from scrutator.modules.base import ModuleContext

        class Resolver:
            async def lookup(self, name, rtype):
                return []

        async with httpx.AsyncClient(follow_redirects=True) as client:
            yield ModuleContext(http=client, resolver=Resolver())

    monkeypatch.setattr(cli, "open_context", real_http)
    with respx.mock() as router:
        router.get("https://crt.sh/").mock(return_value=httpx.Response(200, text='["changed"]'))
        result = runner.invoke(cli.app, ["verify", str(bundle), "--replay"])
    assert result.exit_code == 0, result.output
    assert "replay: 0 unchanged, 1 changed" in result.output


def test_diff_compares_scans_in_a_database_and_bundles(tmp_path):
    db = make_db(tmp_path)
    store = Store(db)
    second = store.create_scan("example.com")
    for value in ("example.com", "www.example.com", "new.example.com"):
        store.upsert_entity(second, Entity(type=EntityType.DOMAIN, value=value), ScopeState.IN)
    store.close()

    text = runner.invoke(cli.app, ["diff", "1", "2", "--db", str(db)])
    assert text.exit_code == 0 and "+ entity domain new.example.com" in text.output
    as_json = runner.invoke(cli.app, ["diff", "1", "2", "--db", str(db), "--json"])
    assert json.loads(as_json.output)["added_entities"][0]["value"] == "new.example.com"
    missing = runner.invoke(cli.app, ["diff", "1", "9", "--db", str(db)])
    assert missing.exit_code == 2

    key_dir, _ = keygen(tmp_path)
    one, two = tmp_path / "1.scrutator", tmp_path / "2.scrutator"
    runner.invoke(cli.app, ["export", "1", "--db", str(db), "--bundle", str(one), "--key-dir", str(key_dir)])
    runner.invoke(cli.app, ["export", "2", "--db", str(db), "--bundle", str(two), "--key-dir", str(key_dir)])
    between = runner.invoke(cli.app, ["diff", str(one), str(two)])
    assert between.exit_code == 0 and "+ entity domain new.example.com" in between.output


def test_diff_refuses_a_bundle_that_fails_verification(tmp_path):
    db = make_db(tmp_path)
    key_dir, _ = keygen(tmp_path)
    good = tmp_path / "g.scrutator"
    runner.invoke(cli.app, ["export", "--db", str(db), "--bundle", str(good), "--key-dir", str(key_dir)])
    files = read_raw(good).files
    files["audit.jsonl"] = files["audit.jsonl"] + b" "
    bad = tmp_path / "b.scrutator"
    with zipfile.ZipFile(bad, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    result = runner.invoke(cli.app, ["diff", str(good), str(bad)])
    assert result.exit_code == 2 and "verification" in result.output


def fake_scan_factory(plan):
    runs = iter(plan)

    async def fake_run_scan(seed, scope, store, ctx, **kwargs):
        sid = store.create_scan(seed.value)
        store.upsert_entity(sid, seed, ScopeState.IN)
        for label in next(runs):
            store.upsert_entity(sid, Entity(type=EntityType.DOMAIN, value=f"{label}.{seed.value}"), ScopeState.IN)
        return sid, AgentStats(rounds=1, modules_run=1, entities=1)

    return fake_run_scan


def test_watch_runs_diffs_and_posts_to_the_webhook(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "run_scan", fake_scan_factory([["a"], ["a", "b"]]))
    out = tmp_path / "w"
    with respx.mock() as router:
        route = router.post("https://hooks.example.test/x").mock(return_value=httpx.Response(200))
        result = runner.invoke(
            cli.app,
            ["watch", "example.com", "--every", "1h", "--max-runs", "2", "--out", str(out), "--webhook", "https://hooks.example.test/x"],
        )
    assert result.exit_code == 0, result.output
    assert "Run 1" in result.output and "Run 2" in result.output and "+ entity domain b.example.com" in result.output
    assert route.call_count == 1
    assert (out / "diff-2.json").exists()


def test_watch_rejects_bad_intervals_and_webhooks(tmp_path):
    base = ["watch", "example.com", "--out", str(tmp_path / "w"), "--max-runs", "1"]
    assert runner.invoke(cli.app, [*base, "--every", "often"]).exit_code == 2
    assert runner.invoke(cli.app, [*base, "--webhook", "http://hooks.example.test/x"]).exit_code == 2


def test_scan_can_write_a_proof_bundle(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "run_scan", fake_scan_factory([["a"]]))
    key_dir, _ = keygen(tmp_path)
    out = tmp_path / "o"
    result = runner.invoke(cli.app, ["scan", "example.com", "--out", str(out), "--bundle", "--key-dir", str(key_dir)])
    assert result.exit_code == 0, result.output
    assert (out / "proof.scrutator").exists() and "Proof bundle" in result.output
    assert runner.invoke(cli.app, ["verify", str(out / "proof.scrutator")]).exit_code == 0


def test_scan_with_bundle_but_no_key_fails_before_scanning(tmp_path, monkeypatch):
    called = []

    async def spy(*args, **kwargs):
        called.append(1)

    monkeypatch.setattr(cli, "run_scan", spy)
    result = runner.invoke(cli.app, ["scan", "example.com", "--out", str(tmp_path / "o"), "--bundle", "--key-dir", str(tmp_path / "none")])
    assert result.exit_code == 2 and "keygen" in result.output and called == []
