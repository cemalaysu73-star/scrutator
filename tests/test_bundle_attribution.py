import json

import pytest
from attrlab import run_lab
from attrscan import scan
from bundlefix import Fixture
from riskbundlefix import forge_report

from scrutator.attribution.promote import promote
from scrutator.bundle.keys import generate_keypair, load_private_key, private_key_path
from scrutator.bundle.reader import read_raw
from scrutator.bundle.verify import verify_bundle
from scrutator.bundle.writer import create_bundle
from scrutator.packs import PackSet
from scrutator.report import build_report

NOW = "2026-10-17T09:30:00+00:00"


def check(report, name):
    return next(c for c in report.checks if c.name == name)


def failing(report):
    return sorted(c.name for c in report.checks if not c.ok)


def report_of(path):
    return json.loads(read_raw(path).files["report.json"])


def candidate(report, entity_id):
    return next(c for c in report["attribution"]["candidates"] if c["entity_id"] == entity_id)


async def bundle(run, tmp_path, *, lead=True):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text("domains:\n  - example.com\n", encoding="utf-8")
    promote(run.store, run.scan_id, "domain:partner.test", scope_file=scope_file, via="cli", now=NOW)
    if lead:
        evidence = candidate(build_report(run.store, run.scan_id), "domain:partner.test")["evidence_ids"][0]
        run.store.add_lead(run.scan_id, kind="lead", claim="A certificate lists example.com next to partner.test.", entity_ids=["domain:partner.test"], evidence_ids=[evidence], status="verified")
    key_dir = tmp_path / "keys"
    fp = generate_keypair(key_dir)
    private = load_private_key(private_key_path(key_dir))
    path = tmp_path / "proof.scrutator"
    create_bundle(run.store, run.scan_id, private, path)
    return Fixture(path, private, fp, run.store, run.scan_id, {})


@pytest.fixture
async def fx(http, tmp_path):
    return await bundle(await scan(http, attribution=True), tmp_path)


def forged(fx, tmp_path, change_report=None, change_manifest=None):
    return verify_bundle(forge_report(fx.path, tmp_path / "forged.scrutator", fx.private, change_report, change_manifest))


async def test_a_genuine_bundle_with_attribution_a_promotion_and_a_lead_passes_every_check(fx):
    result = verify_bundle(fx.path)
    assert result.ok, [c for c in result.checks if not c.ok]
    assert {c.name for c in result.checks} >= {"attribution derivable", "promotions recorded", "risks derivable", "report references"}
    report = report_of(fx.path)
    manifest = json.loads(read_raw(fx.path).files["manifest.json"])
    assert manifest["analysis"]["attribution"] == {"ruleset": 2, "candidates": len(report["attribution"]["candidates"])}
    assert [p["entity"] for p in report["promotions"]] == ["domain:partner.test"] and len(report["leads"]["verified"]) == 1
    assert len(result.warnings) == 1 and "not pinned" in result.warnings[0]


async def test_a_raised_band_is_caught_even_when_resigned_with_the_real_key(fx, tmp_path):
    def raise_band(report):
        item = candidate(report, "domain:_spf.vendor2.test")
        item["band"], item["score"] = "confirmed", 0.99

    result = forged(fx, tmp_path, raise_band)
    assert check(result, "signature valid").ok
    assert failing(result) == ["attribution derivable"]


@pytest.mark.parametrize(
    "tamper",
    [
        lambda c: c.update(premortem=[]),  # hide the caveats
        lambda c: c["signals"].pop(),  # drop a signal
        lambda c: c["signals"][0].update(weight=0.99),  # inflate one
        lambda c: c.update(explanation="partner.test is certainly ours."),
        lambda c: c.update(state="in"),
    ],
)
async def test_any_change_to_a_candidate_is_caught(fx, tmp_path, tamper):
    result = forged(fx, tmp_path, lambda report: tamper(candidate(report, "domain:t0.test")))
    assert failing(result) == ["attribution derivable"]


async def test_a_candidate_added_or_removed_is_caught(fx, tmp_path):
    def remove(report):
        report["attribution"]["candidates"] = [c for c in report["attribution"]["candidates"] if c["entity_id"] != "domain:_spf.vendor2.test"]

    result = forged(fx, tmp_path, remove)
    assert "attribution derivable" in failing(result)


async def test_a_manifest_that_misstates_the_attribution_fails_the_analysis_record(fx, tmp_path):
    def lie(manifest):
        manifest["analysis"]["attribution"]["candidates"] += 5

    result = forged(fx, tmp_path, change_manifest=lie)
    assert failing(result) == ["analysis recorded"]
    result = forged(fx, tmp_path, change_manifest=lambda m: m["analysis"].pop("attribution"))
    assert "analysis recorded" in failing(result)


async def test_a_promotion_cannot_be_added_removed_or_undone_in_the_report(fx, tmp_path):
    result = forged(fx, tmp_path, lambda report: report["promotions"].clear())
    assert failing(result) == ["promotions recorded"]

    def invent(report):
        report["promotions"].append({"entity": "domain:t0.test", "score": 0.99, "band": "confirmed", "evidence_ids": [], "via": "cli", "at": NOW, "scope_file": "scope.yaml"})

    assert "promotions recorded" in failing(forged(fx, tmp_path, invent))

    def undo(report):
        next(e for e in report["entities"] if e["id"] == "domain:partner.test")["state"] = "candidate"

    assert "promotions recorded" in failing(forged(fx, tmp_path, undo))


async def test_a_lead_must_cite_evidence_in_the_bundle_and_an_entity_in_the_report(fx, tmp_path):
    def nowhere(report):
        report["leads"]["verified"][0]["evidence_ids"] = ["0" * 64]

    assert failing(forged(fx, tmp_path, nowhere)) == ["report references"]

    def stranger(report):
        report["leads"]["verified"][0]["entity_ids"] = ["domain:nobody.test"]

    result = forged(fx, tmp_path, stranger)
    assert failing(result) == ["report references"] and "nobody.test" in check(result, "report references").detail


async def test_attribution_that_cites_missing_evidence_fails_the_references(fx, tmp_path):
    def nowhere(report):
        candidate(report, "domain:partner.test")["premortem"].append({"text": "x", "evidence_ids": ["0" * 64]})

    assert "report references" in failing(forged(fx, tmp_path, nowhere))


async def test_changed_pack_data_cannot_be_used_to_re_derive_a_different_attribution(fx, tmp_path):
    def swap_packs(report):
        packs = PackSet.from_dict(report["packs"]).to_dict()
        packs["effective"]["signals"].append(
            {"id": "x", "source": "https://example.net/x", "verified": True, "note": "", "examples": [], "signal": "cert_san", "frequency": 0.9, "sample_size": 10}
        )
        report["packs"] = packs

    assert "packs intact" in failing(forged(fx, tmp_path, swap_packs))


async def test_a_bundle_from_before_attribution_still_verifies(fx, tmp_path):
    def strip(report):
        for key in ("attribution", "promotions", "leads"):
            report.pop(key)
        report["summary"].pop("candidates"), report["summary"].pop("leads")

    result = forged(fx, tmp_path, strip, lambda manifest: manifest["analysis"].pop("attribution"))
    assert result.ok, [c for c in result.checks if not c.ok]
    assert check(result, "attribution derivable").detail == "bundle predates attribution"
    assert not any(c.name == "promotions recorded" for c in result.checks)


async def test_an_attribution_made_by_another_rule_set_is_not_re_derived_but_is_flagged(fx, tmp_path):
    def other(manifest):
        manifest["analysis"]["attribution"]["ruleset"] = 7

    def other_report(report):
        report["attribution"]["ruleset"] = 7

    result = forged(fx, tmp_path, other_report, other)
    assert result.ok and any("rule set 7" in w for w in result.warnings)
    assert not any(c.name == "attribution derivable" for c in result.checks)


async def test_the_lab_bundle_verifies_and_a_forged_band_does_not(http, tmp_path):
    lab = await run_lab(http, tmp_path)
    fixture = await bundle(lab, tmp_path, lead=False)
    assert verify_bundle(fixture.path, pinned_fingerprint=fixture.fingerprint).ok

    def inflate(report):
        candidate(report, "domain:partner.test")["band"] = "confirmed"

    result = verify_bundle(forge_report(fixture.path, tmp_path / "lab-forged.scrutator", fixture.private, inflate), pinned_fingerprint=fixture.fingerprint)
    assert failing(result) == ["attribution derivable"]
