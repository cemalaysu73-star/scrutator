import json

import pytest
from attrlab import EXPECTED, LAB, ORG, STRANGERS, TRUTH, UNDISCOVERABLE, bands, run_lab
from packfix import provider, write_pack

from scrutator.attribution import attribute, evaluate
from scrutator.attribution.promote import promote
from scrutator.model import ScopeState
from scrutator.packs import load_packs
from scrutator.report import build_report
from scrutator.scope import ScopePolicy


@pytest.fixture
async def lab(http, tmp_path):
    return await run_lab(http, tmp_path)


def listed(report):
    return {c["entity_id"]: c for c in report["attribution"]["candidates"]}


def test_the_lab_has_the_shape_its_documentation_says():
    assert len(TRUTH) == 16 and UNDISCOVERABLE == {"hidden.test"}
    assert {n for n, spec in LAB.items() if not spec["true"]} == {
        "client.test", "partner.test", "tinyhost.test", "hosting-client.test", "cf-blog.test", "_spf.vendor-mail.test",
    }
    assert len(STRANGERS) == 25 and ORG == "Example Corporation"
    assert {n for names in EXPECTED.values() for n in names} >= {n for n in LAB if n not in UNDISCOVERABLE}


# the exit criterion --------------------------------------------------------------------------------------


def test_precision_in_the_probable_band_is_at_least_nine_in_ten(lab):
    result = evaluate(lab.report["attribution"], TRUTH)
    assert result["probable"]["count"] == 5 and result["probable"]["precision"] >= 0.9  # the band itself
    assert result["probable"]["or_better_count"] == 12 and result["probable"]["or_better_precision"] >= 0.9  # everything called probable or better


def test_the_published_numbers_for_every_band_are_the_measured_ones(lab):
    """The README publishes this table. A change in scoring that moves a number must move the README."""
    result = evaluate(lab.report["attribution"], TRUTH)
    table = {band: (r["count"], r["true"], r["precision"], r["or_better_precision"], r["or_better_recall"]) for band, r in result.items()}
    assert table == {
        "confirmed": (7, 6, 0.8571, 0.8571, 0.375),
        "probable": (5, 5, 1.0, 0.9167, 0.6875),
        "possible": (5, 3, 0.6, 0.8235, 0.875),
        "unlikely": (31, 1, 0.0323, 0.3125, 0.9375),
    }


def test_every_name_lands_in_the_band_the_scoring_was_designed_to_give_it(lab):
    got = bands(lab.report)
    for band, names in EXPECTED.items():
        assert {n: got.get(n) for n in names} == {n: band for n in names}, band
    assert set(got) == {n for names in EXPECTED.values() for n in names}


def test_the_planted_false_positives_are_exactly_the_ones_documented(lab):
    got = bands(lab.report)
    wrong = {band: sorted(n for n, b in got.items() if b == band and f"domain:{n}" not in TRUTH) for band in ("confirmed", "probable", "possible")}
    assert wrong == {"confirmed": ["client.test"], "probable": [], "possible": ["partner.test", "tinyhost.test"]}
    missed = sorted(n for n in (n.removeprefix("domain:") for n in TRUTH) if got.get(n) in (None, "unlikely"))
    assert missed == ["archive.test", "hidden.test"]  # one found but not believed, one never found


def test_a_true_name_nothing_links_to_the_scope_is_never_found_or_queried(lab):
    assert "hidden.test" not in {name for name, _ in lab.dns.calls}
    assert "domain:hidden.test" not in {e["id"] for e in lab.report["entities"]}


def test_shared_providers_and_strangers_do_not_make_a_candidate_believable(lab):
    found = listed(lab.report)
    cloudflare = next(s for s in found["domain:cf-blog.test"]["signals"] if s["kind"] == "shared_ns")
    hosting = next(s for s in found["domain:hosting-client.test"]["signals"] if s["kind"] == "network_owner")
    assert cloudflare["weight"] == 0 and "Cloudflare" in cloudflare["note"]
    assert hosting["weight"] == 0 and "Example Hosting" in hosting["note"]
    assert all(found[f"domain:{n}"]["band"] == "unlikely" and found[f"domain:{n}"]["score"] < 0.25 for n in STRANGERS)
    assert not any(s["weight"] > 0 for s in found["domain:partner.test"]["signals"] if s["kind"] == "rdap_registrant")  # a redacted registrant ties nothing


# what the scan is allowed to touch --------------------------------------------------------------------------


def test_only_the_scope_and_the_selected_candidates_were_ever_queried(lab):
    scope = ScopePolicy(domains=["example.com"])
    selected = {r["entity"].removeprefix("domain:") for r in lab.store.audit_log(lab.scan_id) if r["event"] == "candidate"}
    assert selected and "pay.test" in selected and "hidden.test" not in selected
    allowed = selected | {f"_dmarc.{n}" for n in selected}
    queried = {name for name, _ in lab.dns.calls}
    assert all(scope.decide(n).allowed or n in allowed for n in queried), sorted(n for n in queried if not scope.decide(n).allowed and n not in allowed)
    for kind, value in lab.http_log:
        if kind == "crt":
            assert value.removeprefix("%.") in {"example.com"} | selected | {n for n in queried if scope.decide(n).allowed}
        if kind == "rdap":
            assert scope.decide(value).allowed or value in selected
    stored = lab.store.entities(lab.scan_id)
    states = {s.entity.value: s.state for s in stored}
    assert states["pay.test"] is ScopeState.CANDIDATE and states["ns1.corp-dns.test"] is ScopeState.CANDIDATE
    assert [s.entity.id for s in stored if s.entity.type.value == "domain" and s.state is ScopeState.IN and not scope.decide(s.entity.value).allowed] == []


def test_every_candidate_cites_evidence_that_exists_and_names_it(lab):
    evidence = lab.report["evidence"]
    for item in lab.report["attribution"]["candidates"]:
        assert item["evidence_ids"] and set(item["evidence_ids"]) <= set(evidence)
        text = " ".join(evidence[i]["request"] + " " + evidence[i]["payload"] for i in item["evidence_ids"])
        assert item["value"] in text, item["value"]
        for premortem in item["premortem"]:
            assert premortem["evidence_ids"] and set(premortem["evidence_ids"]) <= set(item["evidence_ids"])


def test_the_attribution_can_be_recomputed_from_the_report_alone(lab):
    report = json.loads(json.dumps(lab.report))
    assert attribute(report) == report["attribution"]
    assert build_report(lab.store, lab.scan_id)["attribution"] == lab.report["attribution"]


# knowledge is data -------------------------------------------------------------------------------------------


def test_a_provider_entry_for_a_small_dns_operator_changes_the_result_without_any_code(lab, tmp_path):
    extra = write_pack(tmp_path / "extra", "dns-operator.yaml", "providers", [provider("corp-dns", provider="Corp DNS", ns=["corp-dns.test"])])
    packs = load_packs([tmp_path / "lab-packs", extra])
    after = bands(build_report(lab.store, lab.scan_id, packs=packs))
    before = bands(lab.report)
    assert (before["partner.test"], before["tinyhost.test"], before["b2b.test"]) == ("possible", "possible", "possible")
    assert after["tinyhost.test"] == "unlikely"  # stale certificate only, now that the name servers are a known provider
    assert after["partner.test"] == "possible" and after["b2b.test"] == "possible"  # a certificate alone, and a certificate plus a network
    assert "ns1.corp-dns.test" not in after  # the scope pointing at a known provider is no signal at all
    scores = {c["value"]: c["score"] for c in build_report(lab.store, lab.scan_id, packs=packs)["attribution"]["candidates"]}
    assert scores["partner.test"] == 0.6 and scores["tinyhost.test"] == 0.3 and scores["b2b.test"] == 0.74


# promotion ---------------------------------------------------------------------------------------------------


async def test_promoting_a_candidate_puts_it_in_scope_for_the_next_scan(lab, http, tmp_path):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text("domains:\n  - example.com\n", encoding="utf-8")
    promote(lab.store, lab.scan_id, "domain:pay.test", scope_file=scope_file, via="cli", now="2026-10-17T10:00:00+00:00")
    assert lab.store.verify_audit(lab.scan_id)

    policy = ScopePolicy.from_file(scope_file)
    assert policy.decide("www.pay.test").allowed and not policy.decide("eu.test").allowed
    again = await run_lab(http, tmp_path, scope=policy.to_dict()["domains"], store=lab.store, dns=lab.dns, packs=lab.packs)
    assert again.scan_id != lab.scan_id
    assert "domain:pay.test" not in listed(again.report)  # in scope now, so nothing left to attribute
    assert next(e for e in again.report["entities"] if e["id"] == "domain:pay.test")["state"] == "in"
    assert "domain:eu.test" in listed(again.report)  # the others are still only candidates
    assert [p["entity"] for p in build_report(lab.store, lab.scan_id)["promotions"]] == ["domain:pay.test"]
