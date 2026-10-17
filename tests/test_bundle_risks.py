import json

import pytest
from packfix import provider, write_pack
from riskbundlefix import forge_report, make_risky_bundle

from scrutator.bundle import verify as verify_module
from scrutator.bundle.reader import read_raw
from scrutator.bundle.verify import verify_bundle
from scrutator.packs import PackSet, load_packs
from scrutator.risk.engine import RULESET_VERSION, analyze


def check(report, name):
    return next(c for c in report.checks if c.name == name)


def failing(report):
    return sorted(c.name for c in report.checks if not c.ok)


def report_of(path):
    return json.loads(read_raw(path).files["report.json"])


def test_a_genuine_bundle_carries_risks_and_passes_every_check(tmp_path):
    fx = make_risky_bundle(tmp_path)
    report = verify_bundle(fx.path)
    assert report.ok, [c for c in report.checks if not c.ok]
    assert {c.name for c in report.checks} >= {"analysis recorded", "packs intact", "risks derivable", "findings derivable"}
    data = report_of(fx.path)
    assert [r["rule_id"] for r in data["risks"]] == ["dangling-cname-claimable", "spf-allows-all", "ghost-hostname"]
    manifest = json.loads(read_raw(fx.path).files["manifest.json"])
    analysis = manifest["analysis"]
    assert analysis["ruleset"] == RULESET_VERSION and analysis["risks"] == 3
    assert analysis["effective_sha256"] == data["packs"]["effective_sha256"]
    assert {p["name"] for p in analysis["packs"]} == {"providers.yaml", "takeover.yaml", "signals.yaml", "playbooks.yaml"}
    assert len(report.warnings) == 1 and "not pinned" in report.warnings[0]


def test_risks_are_part_of_what_a_bundle_must_cite(tmp_path):
    fx = make_risky_bundle(tmp_path)

    def point_nowhere(report):
        report["risks"][0]["evidence_ids"] = ["0" * 64]

    result = verify_bundle(forge_report(fx.path, tmp_path / "f.scrutator", fx.private, point_nowhere))
    assert not check(result, "report references").ok


def test_a_lowered_severity_is_caught_even_when_resigned_with_the_real_key(tmp_path):
    fx = make_risky_bundle(tmp_path)

    def lower(report):
        report["risks"][0]["severity"] = "low"

    result = verify_bundle(forge_report(fx.path, tmp_path / "f.scrutator", fx.private, lower))
    assert check(result, "signature valid").ok
    assert failing(result) == ["risks derivable"]


def test_a_hidden_risk_is_caught(tmp_path):
    fx = make_risky_bundle(tmp_path)

    def hide(report):
        del report["risks"][1]

    result = verify_bundle(forge_report(fx.path, tmp_path / "f.scrutator", fx.private, hide))
    assert check(result, "signature valid").ok
    assert {"risks derivable", "analysis recorded"} <= set(failing(result))


def test_hiding_a_risk_and_fixing_the_manifest_count_is_still_caught(tmp_path):
    fx = make_risky_bundle(tmp_path)

    def hide(report):
        del report["risks"][1]

    def recount(manifest):
        manifest["analysis"]["risks"] = 2

    result = verify_bundle(forge_report(fx.path, tmp_path / "f.scrutator", fx.private, hide, recount))
    assert failing(result) == ["risks derivable"]


def test_a_risk_that_cites_different_evidence_is_caught(tmp_path):
    fx = make_risky_bundle(tmp_path)

    def swap(report):
        spf, ghost = report["risks"][1], report["risks"][2]
        spf["evidence_ids"] = ghost["evidence_ids"]

    result = verify_bundle(forge_report(fx.path, tmp_path / "f.scrutator", fx.private, swap))
    assert failing(result) == ["risks derivable"]


def test_a_fabricated_risk_is_caught_even_though_its_evidence_exists(tmp_path):
    fx = make_risky_bundle(tmp_path)

    def invent(report):
        risk = dict(report["risks"][0], rule_id="spf-no-all", severity="high", explanation="Invented.")
        report["risks"].append(risk)

    def recount(manifest):
        manifest["analysis"]["risks"] = 4

    result = verify_bundle(forge_report(fx.path, tmp_path / "f.scrutator", fx.private, invent, recount))
    assert failing(result) == ["risks derivable"]


def test_a_changed_dependency_map_is_caught(tmp_path):
    fx = make_risky_bundle(tmp_path)
    assert {d["provider"] for d in report_of(fx.path)["dependencies"]} == {"Let's Encrypt", "Microsoft Azure", "Google Workspace"}

    def add(report):
        report["dependencies"].append({"category": "dns", "provider": "Nobody", "verified": True, "via": [], "hostnames": [], "targets": [], "evidence_ids": []})

    result = verify_bundle(forge_report(fx.path, tmp_path / "f.scrutator", fx.private, add))
    assert failing(result) == ["risks derivable"]


def test_removing_a_takeover_fingerprint_and_recomputing_everything_is_caught_by_the_pack_check(tmp_path):
    fx = make_risky_bundle(tmp_path)

    def downgrade(report):
        packs = report["packs"]
        packs["effective"]["takeover"] = [e for e in packs["effective"]["takeover"] if e["id"] != "microsoft-azure"]
        edited = PackSet.from_dict(packs)
        packs["effective_sha256"] = edited.effective_sha256  # a careful forger fixes the hash too
        analysis = analyze(report, edited)
        report["risks"], report["dependencies"] = analysis["risks"], analysis["dependencies"]
        rules = [r["rule_id"] for r in report["risks"]]
        assert "dangling-cname" in rules and "dangling-cname-claimable" not in rules  # the forgery really downgrades it

    forged = forge_report(fx.path, tmp_path / "f.scrutator", fx.private, downgrade)
    result = verify_bundle(forged)
    assert check(result, "signature valid").ok
    assert not check(result, "packs intact").ok
    assert "differs from this tool's bundled pack" in check(result, "packs intact").detail or "content differs" in check(result, "packs intact").detail
    assert not result.ok


def test_pack_entries_that_do_not_match_their_declared_hash_are_caught(tmp_path):
    fx = make_risky_bundle(tmp_path)

    def tamper(report):
        report["packs"]["effective"]["takeover"].pop(0)

    result = verify_bundle(forge_report(fx.path, tmp_path / "f.scrutator", fx.private, tamper))
    assert not check(result, "packs intact").ok


def test_a_manifest_that_promises_an_analysis_the_report_lacks_is_caught(tmp_path):
    fx = make_risky_bundle(tmp_path)

    def strip(report):
        for key in ("risks", "dependencies", "packs"):
            del report[key]

    result = verify_bundle(forge_report(fx.path, tmp_path / "f.scrutator", fx.private, strip))
    assert not check(result, "analysis recorded").ok and not result.ok


def test_a_bundle_from_before_risk_analysis_still_verifies(tmp_path):
    fx = make_risky_bundle(tmp_path)

    def strip(report):
        for key in ("risks", "dependencies", "packs"):
            del report[key]
        report["summary"].pop("risks", None)

    def legacy(manifest):
        del manifest["analysis"]

    result = verify_bundle(forge_report(fx.path, tmp_path / "f.scrutator", fx.private, strip, legacy))
    assert result.ok, [c for c in result.checks if not c.ok]
    assert check(result, "risks derivable").detail == "bundle predates risk analysis"


def test_user_packs_travel_with_the_bundle_and_pass_with_a_warning(tmp_path):
    write_pack(tmp_path / "mine", "mine.yaml", "providers", [provider()])
    fx = make_risky_bundle(tmp_path, load_packs([tmp_path / "mine"]))
    result = verify_bundle(fx.path)
    assert result.ok, [c for c in result.checks if not c.ok]
    assert any("user packs" in w for w in result.warnings)
    assert {f["origin"] for f in report_of(fx.path)["packs"]["files"]} == {"bundled", "user"}


def test_with_user_packs_a_bundled_entry_still_cannot_be_removed(tmp_path):
    write_pack(tmp_path / "mine", "mine.yaml", "providers", [provider()])
    fx = make_risky_bundle(tmp_path, load_packs([tmp_path / "mine"]))

    def downgrade(report):
        packs = report["packs"]
        packs["effective"]["takeover"] = [e for e in packs["effective"]["takeover"] if e["id"] != "microsoft-azure"]
        packs["effective_sha256"] = PackSet.from_dict(packs).effective_sha256
        analysis = analyze(report)
        report["risks"], report["dependencies"] = analysis["risks"], analysis["dependencies"]

    result = verify_bundle(forge_report(fx.path, tmp_path / "f.scrutator", fx.private, downgrade))
    assert not check(result, "packs intact").ok and "were removed" in check(result, "packs intact").detail


def test_a_bundle_made_with_other_pack_versions_is_accepted_with_a_warning(tmp_path, monkeypatch):
    fx = make_risky_bundle(tmp_path)
    newer = load_packs()
    newer.files = tuple({**f, "version": "2099.1.1"} for f in newer.files)
    monkeypatch.setattr(verify_module, "_trusted_packs", lambda: newer)
    result = verify_bundle(fx.path)
    assert result.ok and any("other bundled pack versions" in w for w in result.warnings)


def test_a_rule_set_this_tool_does_not_implement_is_not_re_derived(tmp_path):
    fx = make_risky_bundle(tmp_path)

    def newer(manifest):
        manifest["analysis"]["ruleset"] = 99

    result = verify_bundle(forge_report(fx.path, tmp_path / "f.scrutator", fx.private, None, newer))
    assert result.ok and any("rule set 99" in w for w in result.warnings)
    assert "risks derivable" not in {c.name for c in result.checks}


@pytest.mark.parametrize("junk", [None, "text", [1], {"effective": {}, "files": []}, {"effective": "x", "files": []}])
def test_malformed_pack_descriptions_fail_cleanly(tmp_path, junk):
    fx = make_risky_bundle(tmp_path)

    def damage(report):
        report["packs"] = junk

    result = verify_bundle(forge_report(fx.path, tmp_path / "f.scrutator", fx.private, damage))
    assert not result.ok


def test_a_report_that_breaks_the_analysis_in_any_way_fails_the_check_instead_of_crashing(tmp_path):
    fx = make_risky_bundle(tmp_path)

    def poison(report):
        first = next(iter(report["evidence"]))
        report["evidence"][first]["payload"] = 5  # not text: the analysis trips over it

    result = verify_bundle(forge_report(fx.path, tmp_path / "f.scrutator", fx.private, poison))
    assert not result.ok
    assert "malformed risk analysis" in check(result, "risks derivable").detail
