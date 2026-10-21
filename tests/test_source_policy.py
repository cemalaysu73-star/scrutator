"""v0.7 task 3: the user decides which sources a scan may use (an allow list, an exclude list, or
`--no-noncommercial` for work the free tiers' terms do not cover). The policy is recorded in the report,
the signed bundle and the audit log, and `verify` flags a bundle whose evidence contradicts it."""

import json

import pytest
from bundlefix import make_bundle
from riskbundlefix import forge_report
from typer.testing import CliRunner

from scrutator import cli
from scrutator.bundle.verify import verify_bundle
from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules.base import Module, Observation
from scrutator.modules.registry import load_builtin_modules
from scrutator.scan import run_scan
from scrutator.scope import ScopePolicy
from scrutator.sources import SourceError, SourcePolicy
from scrutator.store import Store

D = EntityType.DOMAIN
NONCOMMERCIAL = {"internetdb", "ripestat", "asn", "certspotter", "subdomaincenter"}


def dom(value):
    return Entity(type=D, value=value)


def names(modules):
    return sorted(m.name for m in modules)


@pytest.fixture(scope="module")
def builtin():
    return load_builtin_modules()


def test_the_sources_the_readme_marks_non_commercial_are_flagged_on_the_modules(builtin):
    assert {m.name for m in builtin if m.noncommercial} == NONCOMMERCIAL


def test_by_default_everything_without_a_key_may_run(builtin):
    chosen, disabled = SourcePolicy().select(builtin, env={})
    assert names(chosen) == names([m for m in builtin if not m.needs_key and not m.opt_in])
    # only keyed sources and the opt-in modules (brand presence, organisation exposure) are off, and they say why
    assert all("key" in reason or reason.startswith("opt-in") for reason in disabled.values())
    assert {n for n, reason in disabled.items() if reason.startswith("opt-in")} == {"brand", "axfr", "exposure_site", "exposure_dns", "exposure_rdap", "exposure_repos"}


def test_no_noncommercial_drops_exactly_the_flagged_sources(builtin):
    chosen, disabled = SourcePolicy(no_noncommercial=True).select(builtin, env={})
    assert {n for n, reason in disabled.items() if "non-commercial" in reason} == NONCOMMERCIAL
    assert not {m.name for m in chosen} & NONCOMMERCIAL and "dns" in names(chosen) and "crtsh" in names(chosen)


def test_an_allow_list_runs_only_those_sources_and_a_source_name_covers_all_its_modules(builtin):
    chosen, disabled = SourcePolicy(allow=("crtsh", "dns", "ripestat")).select(builtin, env={})
    assert names(chosen) == ["asn", "crtsh", "dns", "ripestat", "wildcard"]  # ripestat is also the asn source, the probe is DNS
    assert disabled["certspotter"] == "not in --sources"


def test_exclude_wins_over_the_allow_list_and_a_module_name_is_enough(builtin):
    chosen, disabled = SourcePolicy(allow=("crtsh", "dns", "ripestat"), exclude=("asn",)).select(builtin, env={})
    assert "asn" not in names(chosen) and "ripestat" in names(chosen)
    assert "excluded" in disabled["asn"]


def test_unknown_names_are_an_error_that_lists_the_valid_ones(builtin):
    with pytest.raises(SourceError) as caught:
        SourcePolicy.parse("crtsh,certspoter", None, False, builtin)
    message = str(caught.value)
    assert "certspoter" in message and "certspotter" in message and "crtsh" in message
    with pytest.raises(SourceError):
        SourcePolicy.parse(None, "nope", False, builtin)
    with pytest.raises(SourceError):
        SourcePolicy.parse(" , ", None, False, builtin)  # an empty allow list would run nothing


def test_parse_accepts_commas_spaces_and_case(builtin):
    policy = SourcePolicy.parse(" CRTSH, dns ,", "wildcard", True, builtin)
    assert policy.allow == ("crtsh", "dns") and policy.exclude == ("wildcard",) and policy.no_noncommercial


def test_the_policy_round_trips_and_records_what_it_enabled_and_disabled(builtin):
    policy = SourcePolicy(allow=("crtsh", "dns"), no_noncommercial=True)
    record = policy.record(builtin, env={})
    assert record["allow"] == ["crtsh", "dns"] and record["no_noncommercial"] is True and record["exclude"] == []
    assert record["enabled"] == ["crtsh", "dns", "wildcard"] and "certspotter" in record["disabled"]
    assert SourcePolicy.from_dict(record) == policy
    assert SourcePolicy.from_dict(None) == SourcePolicy()


# ------------------------------------------------------------------------------------------ in a scan


class Listing(Module):
    name = "listing"
    accepts = frozenset({D})
    apex_only = True

    async def run(self, entity, ctx):
        return [Observation(dom("www.example.com"), "has_subdomain", Evidence.create("listing", "GET https://list.test/", "x"))]


class Marked(Module):
    name = "marked"
    accepts = frozenset({D})
    noncommercial = True
    apex_only = True

    async def run(self, entity, ctx):
        return [Observation(dom("mkt.example.com"), "has_subdomain", Evidence.create("marked", "GET https://marked.test/", "y"))]


async def scan_with(policy):
    store = Store(":memory:")
    scan_id, _ = await run_scan(
        dom("example.com"), ScopePolicy(domains=["example.com"]), store, ctx=None,
        modules=[Listing(), Marked()], source_policy=policy,
    )
    return store, scan_id


async def test_a_scan_runs_only_the_sources_the_policy_allows_and_records_the_policy_first():
    store, scan_id = await scan_with(SourcePolicy(no_noncommercial=True))
    log = store.audit_log(scan_id)
    assert log[0]["event"] == "source_policy" and log[0]["no_noncommercial"] is True
    assert log[0]["enabled"] == ["listing"] and "marked" in log[0]["disabled"]
    assert not [r for r in log if r.get("module") == "marked"]  # not asked, not even denied
    assert {e.entity.value for e in store.entities(scan_id)} == {"example.com", "www.example.com"}
    assert json.loads(store.get_meta(scan_id, "source_policy")) == {k: v for k, v in log[0].items() if k != "event"}


async def test_without_a_policy_the_scan_still_records_that_nothing_was_restricted():
    store, scan_id = await scan_with(None)
    first = store.audit_log(scan_id)[0]
    assert first["event"] == "source_policy" and first["allow"] is None and first["exclude"] == [] and first["no_noncommercial"] is False
    assert sorted(first["enabled"]) == ["listing", "marked"] and first["disabled"] == {}


async def test_the_report_carries_the_policy():
    from scrutator.report import build_report

    store, scan_id = await scan_with(SourcePolicy(exclude=("listing",)))
    report = build_report(store, scan_id)
    assert report["source_policy"]["exclude"] == ["listing"] and report["source_policy"]["enabled"] == ["marked"]


# ------------------------------------------------------------------------------------------ bundles


async def policy_bundle(tmp_path, policy, inject=None):
    """A real scan under `policy`, packed into a signed bundle; `inject(store, scan_id)` may add evidence the
    policy would not allow, as a compromised collector would."""
    from bundlefix import Fixture
    from scrutator.bundle.keys import generate_keypair, load_private_key, private_key_path
    from scrutator.bundle.writer import create_bundle

    store, scan_id = await scan_with(policy)
    if inject:
        inject(store, scan_id)
    key_dir = tmp_path / "keys"
    fp = generate_keypair(key_dir)
    private = load_private_key(private_key_path(key_dir))
    path = tmp_path / "proof.scrutator"
    manifest = create_bundle(store, scan_id, private, path)
    return Fixture(path, private, fp, store, scan_id, manifest), manifest


async def test_the_manifest_carries_the_policy_and_a_genuine_bundle_passes_the_check(tmp_path):
    fx, manifest = await policy_bundle(tmp_path, SourcePolicy(no_noncommercial=True))
    assert manifest["source_policy"]["no_noncommercial"] is True and manifest["source_policy"]["enabled"] == ["listing"]
    result = verify_bundle(fx.path)
    assert result.ok, [c for c in result.checks if not c.ok]
    assert any(c.name == "source policy honoured" and c.ok for c in result.checks)


async def test_evidence_from_a_source_the_policy_excluded_fails_the_check(tmp_path):
    def smuggle(store, scan_id):
        evidence = Evidence.create("marked", "GET https://marked.test/", "smuggled")
        store.add_evidence(evidence)
        store.add_scan_evidence(scan_id, evidence.id)

    fx, _ = await policy_bundle(tmp_path, SourcePolicy(no_noncommercial=True), inject=smuggle)
    result = verify_bundle(fx.path)
    failed = [c for c in result.checks if not c.ok]
    assert [c.name for c in failed] == ["source policy honoured"] and "marked" in failed[0].detail


async def test_a_lookup_by_an_excluded_module_in_the_signed_audit_log_fails_the_check(tmp_path):
    def sneak(store, scan_id):
        store.append_audit(scan_id, {"event": "ok", "module": "marked", "entity": "domain:example.com", "evidence_ids": []})

    fx, _ = await policy_bundle(tmp_path, SourcePolicy(exclude=("marked",)), inject=sneak)
    result = verify_bundle(fx.path)
    assert [c.name for c in result.checks if not c.ok] == ["source policy honoured"]


async def test_a_report_that_hides_or_softens_the_policy_disagrees_with_the_audit_log(tmp_path):
    fx, _ = await policy_bundle(tmp_path, SourcePolicy(no_noncommercial=True))

    def soften(report):
        report["source_policy"]["no_noncommercial"] = False

    def erase(report):
        del report["source_policy"]

    for change in (soften, erase):
        result = verify_bundle(forge_report(fx.path, tmp_path / "f.scrutator", fx.private, change))
        assert [c.name for c in result.checks if not c.ok] == ["source policy honoured"], change.__name__


async def test_a_manifest_that_disagrees_with_the_report_fails_the_check(tmp_path):
    fx, _ = await policy_bundle(tmp_path, SourcePolicy(no_noncommercial=True))

    def edit(manifest):
        manifest["source_policy"]["no_noncommercial"] = False

    result = verify_bundle(forge_report(fx.path, tmp_path / "f.scrutator", fx.private, change_manifest=edit))
    assert [c.name for c in result.checks if not c.ok] == ["source policy honoured"]


def test_a_bundle_made_before_source_policies_still_verifies(tmp_path):
    fx = make_bundle(tmp_path)
    result = verify_bundle(fx.path)
    assert result.ok and not any(c.name == "source policy honoured" for c in result.checks) or result.ok


# ------------------------------------------------------------------------------------------ the CLI


runner = CliRunner()


@pytest.fixture
def seen(monkeypatch):
    """The CLI with no network and no scan: records the policy `scan` hands to `run_scan`."""
    from contextlib import asynccontextmanager

    from scrutator.agent.runner import AgentStats
    from scrutator.ai.config import AIMode
    from scrutator.model import ScopeState

    calls = []

    @asynccontextmanager
    async def fake_context():
        yield None

    async def no_ai(*args, **kwargs):
        return None, AIMode.OFF

    async def fake_run_scan(seed, scope, store, ctx, **kwargs):
        calls.append(kwargs)
        scan_id = store.create_scan(seed.value)
        store.upsert_entity(scan_id, seed, ScopeState.IN)
        store.set_meta(scan_id, "source_policy", json.dumps(kwargs["source_policy"].record(load_builtin_modules(), env={})))
        return scan_id, AgentStats(rounds=1, modules_run=1, entities=1)

    monkeypatch.setattr(cli, "open_context", fake_context)
    monkeypatch.setattr(cli, "ai_client", fake_context)
    monkeypatch.setattr(cli, "build_runtime", no_ai)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    return calls


def test_scan_passes_the_policy_to_the_scan(tmp_path, seen):
    result = runner.invoke(cli.app, ["scan", "example.com", "--out", str(tmp_path / "o"), "--sources", "crtsh,dns", "--exclude-sources", "wildcard", "--no-noncommercial"])
    assert result.exit_code == 0, result.output
    policy = seen[0]["source_policy"]
    assert policy.allow == ("crtsh", "dns") and policy.exclude == ("wildcard",) and policy.no_noncommercial


def test_scan_without_the_options_runs_with_the_default_policy(tmp_path, seen):
    assert runner.invoke(cli.app, ["scan", "example.com", "--out", str(tmp_path / "o")]).exit_code == 0
    assert seen[0]["source_policy"] == SourcePolicy()


def test_scan_rejects_an_unknown_source_before_doing_anything(tmp_path, seen):
    result = runner.invoke(cli.app, ["scan", "example.com", "--out", str(tmp_path / "o"), "--sources", "crtsh,certspoter"])
    assert result.exit_code == 2 and "certspoter" in result.output and "certspotter" in result.output
    assert seen == []


def test_scan_says_which_sources_are_off(tmp_path, seen):
    result = runner.invoke(cli.app, ["scan", "example.com", "--out", str(tmp_path / "o"), "--no-noncommercial"])
    assert result.exit_code == 0
    assert "Sources off: " in result.output and "certspotter" in result.output
    out = tmp_path / "o"
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["source_policy"]["no_noncommercial"] is True


def test_watch_accepts_the_same_options(tmp_path, monkeypatch, seen):
    monkeypatch.setattr(cli, "_sleep", lambda s: __import__("asyncio").sleep(0))
    result = runner.invoke(cli.app, ["watch", "example.com", "--out", str(tmp_path / "w"), "--max-runs", "1", "--no-noncommercial", "--exclude-sources", "wayback"])
    assert result.exit_code == 0, result.output
    assert seen[0]["source_policy"].no_noncommercial and seen[0]["source_policy"].exclude == ("wayback",)


def test_the_docs_list_exactly_the_sources_that_no_noncommercial_turns_off(builtin):
    """The sources table moved from the README to docs/sources.md (R4); the sentence there must name exactly the
    modules the flag turns off."""
    import re
    from pathlib import Path

    page = (Path(__file__).parent.parent / "docs" / "sources.md").read_text(encoding="utf-8")
    sentence = page.split("`--no-noncommercial` turns off", 1)[1].split("Nothing else changes", 1)[0]
    assert {m.name for m in builtin if m.noncommercial} == set(re.findall(r"`([a-z]+)`", sentence))
