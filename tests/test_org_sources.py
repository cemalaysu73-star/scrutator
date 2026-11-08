"""The organisation sources (`scan --org`): the planted lab (scrutator/benchlab/orglab.py), the section derivation that
`verify` repeats, the risks, the attribution org_record signal, and the hard privacy rules (no person data; the
code-leak secret value never leaves the module)."""

import io
import json
import zipfile

import httpx
import pytest

from scrutator.benchlab import orglab
from scrutator.bundle.keys import generate_keypair, load_private_key, private_key_path
from scrutator.bundle.verify import verify_bundle
from scrutator.bundle.writer import create_bundle
from scrutator.model import Entity, EntityType
from scrutator.modules.base import ModuleContext
from scrutator.modules.registry import load_builtin_modules
from scrutator.org.run import OrgConfig
from scrutator.org.section import organisation
from scrutator.packs import load_packs
from scrutator.report import build_report, render_html, render_json
from scrutator.report.sarif import to_sarif
from scrutator.scan import run_scan
from scrutator.scope import ScopePolicy
from scrutator.sources import SourcePolicy
from scrutator.store import Store

from conftest import FakeResolver

SEED = Entity(type=EntityType.DOMAIN, value="example.com")
PACKS = load_packs()
ORG_NAMES = ("wikidata", "gleif", "hibp", "github", "github_leaks", "packages", "handles")


def org_modules():
    return [m for m in load_builtin_modules() if m.name in ORG_NAMES]


async def org_scan(tmp_path, *, code_leaks=True, lab=None):
    lab = lab or orglab.router()
    store = Store(tmp_path / "org.db")
    scope = ScopePolicy(domains=["example.com"])
    policy = SourcePolicy().opt("wikidata", "gleif", "hibp", "github", "packages", "handles")
    if code_leaks:
        policy = policy.opt("github_leaks")
    config = OrgConfig(code_leaks=code_leaks, self_attested=code_leaks, token_present=code_leaks)
    async with httpx.AsyncClient(transport=lab.transport()) as http:
        ctx = ModuleContext(http=http, resolver=FakeResolver())
        scan_id, _ = await run_scan(
            SEED, scope, store, ctx, modules=org_modules(), packs=PACKS,
            source_policy=policy, attribution=True, org=config,
        )
    return store, scan_id, lab


@pytest.fixture
def token(monkeypatch):
    monkeypatch.setenv("SCRUTATOR_GITHUB_TOKEN", "ghp_" + "x" * 36)


async def test_the_lab_finds_the_planted_organisation(tmp_path, token):
    store, scan_id, lab = await org_scan(tmp_path)
    report = build_report(store, scan_id)
    org = report["organisation"]
    assert org["legal_entities"][0]["legal_name"] == orglab.TRUTH["legal_name"]
    assert org["legal_entities"][0]["confirmed"] is True and org["legal_entities"][0]["basis"] == "lei"
    assert {p["name"] for p in org["parents"]} >= {"Example Holding", orglab.TRUTH["parent"]}
    assert {s["name"] for s in org["subsidiaries"]} >= {"Example Labs", orglab.TRUTH["subsidiary"]}
    assert {d["domain"] for d in org["official_domains"]} == orglab.TRUTH["official_domains"]
    assert org["breaches"][0]["name"] == orglab.TRUTH["breach"]
    assert org["github"]["resolved"] and org["github"]["public_members"] == orglab.TRUTH["github_members"]
    assert set(org["github"]["named_in_scope_hosts"]) == orglab.TRUTH["github_named_hosts"]
    assert "old.example.com" in org["github"]["abandoned_named_hosts"]  # the archived repo's homepage
    assert (org["packages"]["confirmed_namespaces"][0]["registry"], org["packages"]["confirmed_namespaces"][0]["name"]) == orglab.TRUTH["confirmed_namespace"]
    assert any((p["registry"], p["name"]) == orglab.TRUTH["unregistered"] for p in org["packages"]["unregistered_brand"])
    assert any((p["registry"], p["name"]) == orglab.TRUTH["lookalike_package"] for p in org["packages"]["lookalikes_existing"])
    states = {(h["platform"], h["handle"]): h["state"] for h in org["handles"]}
    assert states[("gitlab", "example")] == "exists" and states[("bluesky", "example.com")] == "exists"
    assert states[("bluesky", "example.bsky.social")] == "absent" and states[("dockerhub", "example")] == "absent"


async def test_name_match_is_not_confirmed(tmp_path, token):
    # GLEIF is reached by the LEI Wikidata holds, so the entity is confirmed; an exact-name-only hit would be unconfirmed
    store, scan_id, _ = await org_scan(tmp_path)
    org = build_report(store, scan_id)["organisation"]
    assert all(e["confirmed"] for e in org["legal_entities"])


async def test_official_domains_become_org_record_candidates(tmp_path, token):
    store, scan_id, _ = await org_scan(tmp_path)
    report = build_report(store, scan_id)
    candidates = {c["value"]: c for c in report["attribution"]["candidates"]}
    assert "holding.example" in candidates and "labs.example" in candidates
    assert any(s["kind"] == "org_record" for s in candidates["holding.example"]["signals"])
    assert candidates["holding.example"]["band"] in ("possible", "probable")


async def test_risks_from_organisation(tmp_path, token):
    store, scan_id, _ = await org_scan(tmp_path)
    report = build_report(store, scan_id)
    rules = {(r["rule_id"], r["severity"]) for r in report["risks"]}
    assert ("breach-history", "info") in rules
    assert ("exposed-credential", "high") in rules
    assert ("brand-namespace-unregistered", "info") in rules
    assert ("lookalike-package-exists", "low") in rules
    assert {r["rule_id"] for r in report["risks"]} == set(orglab.ORG_RULES)  # every planted org rule fires, nothing else


async def test_verify_re_derives_the_section_and_a_tamper_fails(tmp_path, token):
    store, scan_id, _ = await org_scan(tmp_path)
    generate_keypair(tmp_path)
    key = load_private_key(private_key_path(tmp_path))
    create_bundle(store, scan_id, key, tmp_path / "proof.scrutator")
    result = verify_bundle(tmp_path / "proof.scrutator")
    names = {c.name: c for c in result.checks}
    assert names["organisation derivable"].ok, names["organisation derivable"].detail
    assert names["risks derivable"].ok
    assert names["attribution derivable"].ok

    # flip a breach record in the report and re-sign: the section no longer follows from the evidence
    raw = zipfile.ZipFile(tmp_path / "proof.scrutator").read("report.json")
    report = json.loads(raw)
    report["organisation"]["breaches"][0]["pwn_count"] = 999999
    tampered = tmp_path / "tampered.scrutator"
    with zipfile.ZipFile(tmp_path / "proof.scrutator") as zin, zipfile.ZipFile(tampered, "w") as zout:
        for item in zin.namelist():
            zout.writestr(item, json.dumps(report).encode() if item == "report.json" else zin.read(item))
    bad = verify_bundle(tampered)
    assert not {c.name: c for c in bad.checks}["organisation derivable"].ok


async def test_the_secret_value_is_never_stored_anywhere(tmp_path, token):
    store, scan_id, lab = await org_scan(tmp_path)
    report = build_report(store, scan_id)
    generate_keypair(tmp_path)
    key = load_private_key(private_key_path(tmp_path))
    create_bundle(store, scan_id, key, tmp_path / "proof.scrutator")
    blobs = [render_json(report), render_html(report), json.dumps(to_sarif(report))]
    blobs.append((tmp_path / "proof.scrutator").read_bytes().decode("latin-1"))
    for record in report["evidence"].values():
        blobs.append(json.dumps(record))
    # the code-leak finding exists (so the canary is meaningful) but the value is nowhere
    assert any(r.get("source") == "github_leaks" and "code-leak " in r.get("request", "") for r in report["evidence"].values())
    for blob in blobs:
        assert orglab.SECRET_VALUE not in blob


async def test_no_person_data_is_stored(tmp_path, token):
    store, scan_id, _ = await org_scan(tmp_path)
    report = build_report(store, scan_id)
    text = render_json(report)
    assert "nobody@example.com" not in text  # the GitHub org email is dropped


async def test_org_is_opt_in(tmp_path):
    # without --org (no OrgConfig), the organisation modules do not run and there is no section
    lab = orglab.router()
    store = Store(tmp_path / "noorg.db")
    scope = ScopePolicy(domains=["example.com"])
    async with httpx.AsyncClient(transport=lab.transport()) as http:
        ctx = ModuleContext(http=http, resolver=FakeResolver())
        scan_id, _ = await run_scan(SEED, scope, store, ctx, modules=org_modules(), packs=PACKS, source_policy=SourcePolicy())
    report = build_report(store, scan_id)
    assert "organisation" not in report
    assert not lab.calls  # no organisation source was contacted


async def test_names_first_seen_in_the_org_phase_are_resolved_once(tmp_path, token):
    """A host only a repository names would otherwise stay an unchecked claim (the planner has finished): it is asked of
    DNS once, so its state says whether it exists."""
    from scrutator.benchlab.fakes import StatusResolver

    lab = orglab.router()
    store = Store(tmp_path / "org-dns.db")
    resolver = StatusResolver({("example.com", "A"): ["192.0.2.1"], ("api.example.com", "A"): ["192.0.2.10"]})
    modules = org_modules() + [m for m in load_builtin_modules() if m.name == "dns"]
    policy = SourcePolicy().opt("wikidata", "gleif", "hibp", "github", "packages", "handles")
    async with httpx.AsyncClient(transport=lab.transport()) as http:
        ctx = ModuleContext(http=http, resolver=resolver)
        scan_id, _ = await run_scan(SEED, ScopePolicy(domains=["example.com"]), store, ctx, modules=modules, packs=PACKS,
                                    source_policy=policy, org=OrgConfig())
    report = build_report(store, scan_id)
    names = {n["name"]: n for n in report["names"]}
    assert names["api.example.com"]["state"] == "live"
    assert names["old.example.com"]["state"] != "live"
    asked = {e["request"] for e in report["evidence"].values() if e["source"] == "dns"}
    assert any(r.endswith(" old.example.com") for r in asked)  # the dead host was asked, its NXDOMAIN is evidence
    assert ("api.example.com", "A") in resolver.calls and ("old.example.com", "A") in resolver.calls
