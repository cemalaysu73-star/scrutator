import json
import re
from dataclasses import dataclass

import pytest
import respx
from labfix import PLANTED, PLANTED_RULES, SCOPE_DOMAINS, clean_sources, clean_zone, lab_packs_dir, lab_sources, lab_zone
from llmfakes import ScriptedProvider
from riskbundlefix import forge_report
from typer.testing import CliRunner

from scrutator import cli
from scrutator.ai.runtime import AIRuntime
from scrutator.bundle.keys import generate_keypair, load_private_key, private_key_path
from scrutator.bundle.verify import verify_bundle
from scrutator.bundle.writer import create_bundle
from scrutator.model import Entity, EntityType
from scrutator.modules.base import ModuleContext
from scrutator.packs import load_packs
from scrutator.report import build_report, render_html
from scrutator.report.sarif import to_sarif
from scrutator.risk.catalog import RULES
from scrutator.scan import run_scan
from scrutator.scope import ScopePolicy
from scrutator.store import Store
from scrutator.verify.narrative import summarise

runner = CliRunner()
SEED = Entity(type=EntityType.DOMAIN, value="example.com")


@dataclass
class Run:
    store: Store
    scan_id: int
    report: dict
    resolver: object
    urls: list
    packs: object
    db: object


async def scan(tmp_path, http, resolver, sources, packs):
    db = tmp_path / "lab.db"
    store = Store(db)
    ctx = ModuleContext(http=http, resolver=resolver)
    with respx.mock(assert_all_called=False) as router:
        sources(router)
        scan_id, _ = await run_scan(SEED, ScopePolicy(domains=SCOPE_DOMAINS), store, ctx, packs=packs, max_steps=800)
        urls = [str(call.request.url) for call in router.calls]
    return Run(store, scan_id, build_report(store, scan_id), resolver, urls, packs, db)


@pytest.fixture
async def lab(tmp_path, http):
    packs = load_packs([lab_packs_dir(tmp_path / "lab-packs")])
    return await scan(tmp_path, http, lab_zone(), lab_sources, packs)


@pytest.fixture
async def clean(tmp_path, http):
    return await scan(tmp_path, http, clean_zone(), clean_sources, load_packs())


def found(report):
    return {(r["rule_id"], r["entity_ids"][0]) for r in report["risks"]}


# the exit criterion: all planted issues detected ------------------------------------------------


# the two brand-presence rules need a website and platform answers: they are planted in the brand lab instead
# (scrutator/benchlab/brandlab.py, tests/test_brand.py), and this checks that they are
BRAND_RULES = {rule for rule, _, _ in __import__("scrutator.benchlab.brandlab", fromlist=["x"]).TRUTH_RISKS}
# the rules that read active checks (TLS, HTTP, banners, confirmed and stale exposure) need an authorised connection to a server:
# they are planted in the active lab instead (scrutator/benchlab/activelab.py, tests/test_active_report.py)
ACTIVE_RULES = set(__import__("scrutator.benchlab.activelab", fromlist=["x"]).ACTIVE_RULES) - {"exposed-risky-service"}  # that one is also passive
# the organisation-source rules (`scan --org`) read evidence only the organisation phase collects: planted in the org lab
# instead (scrutator/benchlab/orglab.py, tests/test_org_sources.py)
ORG_RULES = set(__import__("scrutator.benchlab.orglab", fromlist=["x"]).ORG_RULES)


def test_the_lab_plants_every_rule_in_the_catalog():
    assert BRAND_RULES == {"brand-handle-unregistered", "brand-lookalike-handle"}
    assert "tls-cert-expired" in ACTIVE_RULES and not ACTIVE_RULES & (PLANTED_RULES | BRAND_RULES)
    assert ORG_RULES == {"breach-history", "exposed-credential", "lookalike-package-exists", "brand-namespace-unregistered"}
    assert not ORG_RULES & (PLANTED_RULES | BRAND_RULES | ACTIVE_RULES)
    assert PLANTED_RULES | BRAND_RULES | ACTIVE_RULES | ORG_RULES == set(RULES)


def test_every_planted_issue_is_detected(lab):
    assert PLANTED <= found(lab.report), sorted(PLANTED - found(lab.report))
    assert {r["rule_id"] for r in lab.report["risks"]} == set(RULES) - BRAND_RULES - ACTIVE_RULES - ORG_RULES
    assert lab.report["summary"]["risks"] == len(lab.report["risks"])


def test_nothing_is_reported_about_the_names_that_are_fine(lab):
    fine = {"domain:www.example.com", "domain:mail.example.com", "domain:ns1.dns.example.net", "domain:ns2.dns.example.net"}
    flagged = {
        entity
        for r in lab.report["risks"]
        if not r["rule_id"].startswith("concentration")
        for entity in r["entity_ids"]
    }
    assert not (fine & flagged), sorted(fine & flagged)


# the exit criterion: 0 risk statements without evidence --------------------------------------------


def test_every_risk_cites_evidence_that_exists_and_mentions_everything_it_is_about(lab):
    evidence = lab.report["evidence"]
    for risk in lab.report["risks"]:
        assert risk["evidence_ids"], risk["rule_id"]
        cited = [evidence[i] for i in risk["evidence_ids"]]  # a KeyError here is an unsupported risk
        text = " ".join(e["request"] + " " + e["payload"] for e in cited)
        for entity in risk["entity_ids"]:
            assert entity.split(":", 1)[1] in text, (risk["rule_id"], entity)
    assert len({r["fingerprint"] for r in lab.report["risks"]}) == len(lab.report["risks"])


def test_the_scan_never_contacted_anything_outside_the_scope(lab):
    policy = ScopePolicy(domains=SCOPE_DOMAINS)
    queried = {name for name, _ in lab.resolver.calls}
    assert queried and all(policy.decide(name).allowed for name in queried), sorted(n for n in queried if not policy.decide(n).allowed)
    assert not any("example.org" in url for url in lab.urls)
    assert any(name.startswith("_dmarc.") for name in queried)
    org = [e for e in lab.report["entities"] if e["value"].endswith("example.org")]
    assert org and all(e["state"] == "out" for e in org)  # recorded, never queried


async def test_the_statements_the_writer_may_publish_about_risks_are_checked_against_the_evidence(lab):
    true_claims = {}

    def writer(system, user, schema):
        listed = re.findall(r"(F\d+): (Risk \([a-z]+\): [^\n]*?) \[", user)
        for ref, claim in listed:
            true_claims[claim] = ref
        statements = [{"text": claim, "finding_refs": [ref]} for claim, ref in list(true_claims.items())[:8]]
        statements.append({"text": "The registrar has been breached.", "finding_refs": [listed[0][0]]})
        statements.append({"text": "Everything is fine.", "finding_refs": [listed[1][0]]})
        return {"statements": statements}

    def verifier(system, user, schema):
        claim = user.split("Evidence:")[0]
        return {"supported": "breached" not in claim and "Everything is fine" not in claim, "reason": "not in the evidence"}

    ai = AIRuntime({"writer": ScriptedProvider(responder=writer, model="w"), "verifier": ScriptedProvider(responder=verifier, model="v")})

    result = await summarise(ai, lab.store, lab.scan_id)
    assert len(result.verified) == 8 and len(result.rejected) == 2
    report = build_report(lab.store, lab.scan_id)
    assert all(s["evidence_ids"] and all(i in report["evidence"] for i in s["evidence_ids"]) for s in report["summary_statements"])
    assert {l["text"] for l in report["unverified_leads"]} == {"The registrar has been breached.", "Everything is fine."}


# a bundle of the lab verifies, and a forged one does not -----------------------------------------


def test_the_lab_bundle_verifies_and_survives_pinning(lab, tmp_path):
    key_dir = tmp_path / "keys"
    fingerprint = generate_keypair(key_dir)
    private = load_private_key(private_key_path(key_dir))
    path = tmp_path / "lab.scrutator"
    create_bundle(lab.store, lab.scan_id, private, path)
    result = verify_bundle(path, pinned_fingerprint=fingerprint)
    assert result.ok, [c for c in result.checks if not c.ok]
    assert any("user packs" in w for w in result.warnings)

    def downgrade(report):
        report["risks"][0]["severity"] = "info"

    forged = forge_report(path, tmp_path / "forged.scrutator", private, downgrade)
    bad = verify_bundle(forged, pinned_fingerprint=fingerprint)
    assert not bad.ok and [c.name for c in bad.checks if not c.ok] == ["risks derivable"]


# adding a provider or a takeover fingerprint is a data entry, nothing else ----------------------


def test_the_same_evidence_reads_differently_with_and_without_the_lab_data(lab):
    with_data = {(r["rule_id"], r["entity_ids"][0]) for r in lab.report["risks"]}
    plain = build_report(lab.store, lab.scan_id, packs=load_packs())  # the bundled packs only
    without = {(r["rule_id"], r["entity_ids"][0]) for r in plain["risks"]}
    assert ("dangling-cname-claimable", "domain:shop.example.com") in with_data
    assert ("dangling-cname", "domain:shop.example.com") in without  # still dangling, no longer known to be claimable
    assert ("dangling-cname-known-service", "domain:docs.example.com") in with_data
    assert ("dangling-cname", "domain:docs.example.com") in without
    assert not any(rule.startswith("concentration") for rule, _ in without)
    assert any(rule == "concentration-dns" for rule, _ in with_data) and any(rule == "concentration-edge" for rule, _ in with_data)
    assert {d["provider"] for d in lab.report["dependencies"]} >= {"Example DNS", "Example Edge", "Let's Encrypt"}


# the other outputs ----------------------------------------------------------------------------------


def test_the_lab_report_renders_as_sarif_and_html(lab):
    sarif = to_sarif(lab.report)
    assert len(sarif["runs"][0]["results"]) == len(lab.report["risks"])
    assert {r["level"] for r in sarif["runs"][0]["results"]} == {"error", "warning", "note"}
    html = render_html(lab.report)
    assert html.count("<script") == 2 and "Risks" in html
    assert json.loads(json.dumps(lab.report)) == lab.report


def test_the_command_line_fails_a_build_on_the_planted_issues(lab):
    db = str(lab.db)
    lab.store.close()
    assert runner.invoke(cli.app, ["risk", "--db", db]).exit_code == 0
    assert runner.invoke(cli.app, ["risk", "--db", db, "--fail-on", "high"]).exit_code == 1


# false-positive control -------------------------------------------------------------------------------


def test_a_well_run_zone_yields_no_risks_at_all(clean):
    assert clean.report["risks"] == []
    assert {d["provider"] for d in clean.report["dependencies"]} >= {"Cloudflare", "Amazon Route 53", "Microsoft 365"}
    assert any(r == "CAA" for _, r in clean.resolver.calls)  # the checks did run; they found nothing to report


def test_the_clean_zone_bundle_verifies(clean, tmp_path):
    key_dir = tmp_path / "keys"
    generate_keypair(key_dir)
    path = tmp_path / "clean.scrutator"
    create_bundle(clean.store, clean.scan_id, load_private_key(private_key_path(key_dir)), path)
    assert verify_bundle(path).ok
