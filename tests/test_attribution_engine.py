import json
from pathlib import Path

from attrfix import AttrZone
from packfix import document, provider, signal, write_pack

from scrutator.attribution import attribute, evaluate
from scrutator.packs import load_packs

PACKS = load_packs()
LIVE = json.loads((Path(__file__).parent / "data" / "example_com_live.json").read_text(encoding="utf-8"))


def scope_zone(unfamiliar_dns=False):
    """example.com with a name server of its own; optionally also on name servers no pack knows
    (which are themselves weak candidates: the scope points its name servers at them)."""
    zone = AttrZone()
    zone.host("example.com", ["192.0.2.1"])
    zone.name("ns1.example.com")
    zone.ns("example.com", ["ns1.tinydns.test", "ns2.tinydns.test"] if unfamiliar_dns else ["ns1.example.com"])
    return zone


def by_id(result):
    return {c["entity_id"]: c for c in result["candidates"]}


def test_two_kinds_of_strong_evidence_confirm_one_kind_only_makes_it_probable():
    zone = scope_zone()
    zone.candidate("both.test")
    zone.ns("both.test", ["ns1.example.com"])
    zone.cert("example.com", "both.test")
    zone.candidate("delegated.test")
    zone.ns("delegated.test", ["ns1.example.com"])
    zone.candidate("certonly.test")
    zone.cert("example.com", "certonly.test", cert_id=2)
    found = by_id(attribute(zone.report(PACKS), PACKS))
    assert (found["domain:both.test"]["score"], found["domain:both.test"]["band"]) == (0.96, "confirmed")
    assert (found["domain:delegated.test"]["score"], found["domain:delegated.test"]["band"]) == (0.9, "probable")
    assert (found["domain:certonly.test"]["score"], found["domain:certonly.test"]["band"]) == (0.6, "possible")


def test_candidates_come_out_strongest_first_with_the_band_counts():
    zone = scope_zone()
    for name, score_ns in (("b.test", True), ("a.test", True), ("c.test", False)):
        zone.candidate(name)
        if score_ns:
            zone.ns(name, ["ns1.example.com"])
        else:
            zone.cert("example.com", name)
    result = attribute(zone.report(PACKS), PACKS)
    assert [c["entity_id"] for c in result["candidates"]] == ["domain:a.test", "domain:b.test", "domain:c.test"]
    assert result["bands"] == {"confirmed": 0, "probable": 2, "possible": 1, "unlikely": 0}
    assert result["ruleset"] == 1


def test_a_name_with_only_provider_evidence_is_not_a_candidate():
    zone = AttrZone()
    zone.host("example.com")
    zone.ns("example.com", ["hera.ns.cloudflare.com", "elliott.ns.cloudflare.com"])
    zone.candidate("partner.test")
    zone.ns("partner.test", ["hera.ns.cloudflare.com", "elliott.ns.cloudflare.com"])
    assert attribute(zone.report(PACKS), PACKS)["candidates"] == []


def test_every_candidate_cites_evidence_that_exists_and_explains_itself():
    zone = scope_zone()
    zone.candidate("both.test")
    zone.ns("both.test", ["ns1.example.com"])
    zone.cert("example.com", "both.test")
    report = zone.report(PACKS)
    (candidate,) = attribute(report, PACKS)["candidates"]
    assert candidate["evidence_ids"] and set(candidate["evidence_ids"]) <= set(report["evidence"])
    assert candidate["evidence_ids"] == sorted({e for s in candidate["signals"] for e in s["evidence_ids"]})
    assert "both.test scores 0.96 (confirmed)" in candidate["explanation"] and "ns_in_scope 0.90" in candidate["explanation"]
    assert candidate["state"] == "candidate"


def test_the_result_is_deterministic_and_survives_a_json_round_trip():
    zone = scope_zone()
    zone.candidate("both.test")
    zone.ns("both.test", ["ns1.example.com"])
    zone.cert("example.com", "both.test")
    report = zone.report(PACKS)
    first = attribute(report, PACKS)
    assert attribute(json.loads(json.dumps(report)), PACKS) == first == json.loads(json.dumps(first))
    assert attribute(report) == first  # the packs embedded in the report give the same answer


def test_the_pre_mortem_says_what_could_make_it_wrong_and_cites_evidence():
    zone = scope_zone()
    zone.candidate("certonly.test")
    zone.cert("example.com", "certonly.test")
    report = zone.report(PACKS)
    (candidate,) = attribute(report, PACKS)["candidates"]
    texts = [p["text"] for p in candidate["premortem"]]
    assert any("Only one kind of evidence" in t for t in texts)
    assert any("partner, a reseller or a shared service" in t for t in texts)
    assert any("has not been looked at" in t for t in texts)
    for item in candidate["premortem"]:
        assert item["evidence_ids"] and set(item["evidence_ids"]) <= set(candidate["evidence_ids"])


def test_a_looked_at_name_with_two_kinds_has_a_shorter_pre_mortem():
    zone = scope_zone()
    zone.candidate("both.test")
    zone.ns("both.test", ["ns1.example.com"])
    zone.cert("example.com", "both.test")
    zone.host("both.test", ["198.51.100.7"], state="candidate")
    (candidate,) = attribute(zone.report(PACKS), PACKS)["candidates"]
    assert candidate["premortem"] == []


def test_a_signal_reduced_or_ignored_shows_up_in_the_pre_mortem():
    zone = scope_zone(unfamiliar_dns=True)
    zone.candidate("big.test")
    zone.cert("example.com", "big.test", *[f"t{n}.test" for n in range(38)])
    zone.ns("big.test", ["ns1.tinydns.test", "ns2.tinydns.test"])
    zone.mx("example.com", ["aspmx.l.google.com"])
    zone.mx("big.test", ["aspmx.l.google.com"])
    candidate = by_id(attribute(zone.report(PACKS), PACKS))["domain:big.test"]
    texts = " ".join(p["text"] for p in candidate["premortem"])
    assert "1 signal(s) were not counted" in texts and "shared_mx" in texts
    assert "The cert_san signal was reduced" in texts and "40 names" in texts


def test_a_measured_frequency_in_a_pack_lowers_a_signal_without_any_code_change(tmp_path):
    zone = scope_zone()
    zone.candidate("certonly.test")
    zone.cert("example.com", "certonly.test")
    report = zone.report(PACKS)
    assert attribute(report, PACKS)["candidates"][0]["band"] == "possible"
    measured = load_packs([write_pack(tmp_path, "freq.yaml", "signals", [signal("cert-san-measured", signal="cert_san", frequency=0.5, sample_size=2000)])])
    (candidate,) = attribute(report, measured)["candidates"]
    assert (candidate["score"], candidate["band"]) == (0.3, "unlikely")
    assert any("seen in 50% of 2000" in s["note"] for s in candidate["signals"])
    assert measured.signals[0].id == "cert-san-measured" and document("signals", [])["kind"] == "signals"


def test_a_provider_entry_for_the_name_servers_demotes_the_candidate(tmp_path):
    zone = scope_zone(unfamiliar_dns=True)
    zone.candidate("tenant.test")
    zone.ns("tenant.test", ["ns1.tinydns.test", "ns2.tinydns.test"])
    report = zone.report(PACKS)
    before = by_id(attribute(report, PACKS))
    assert before["domain:tenant.test"]["band"] == "possible"
    assert before["domain:ns1.tinydns.test"]["band"] == "unlikely"  # the scope points its name servers at it
    known = load_packs([write_pack(tmp_path, "p.yaml", "providers", [provider("tinydns", provider="TinyDNS", ns=["tinydns.test"])])])
    assert attribute(report, known)["candidates"] == []


def test_a_promoted_name_keeps_its_attribution_and_its_state():
    zone = scope_zone()
    zone.name("both.test", "in")  # promoted after the scan: state in, but the recorded scope does not cover it
    zone.ns("both.test", ["ns1.example.com"])
    (candidate,) = attribute(zone.report(PACKS), PACKS)["candidates"]
    assert candidate["state"] == "in" and candidate["band"] == "probable"


def test_a_real_scan_of_example_com_produces_no_candidate_above_unlikely():
    result = attribute(LIVE, PACKS)
    ids = {c["entity_id"]: c for c in result["candidates"]}
    # the only name outside the scope that shares a certificate is a 2016 certificate's m.testexample.com
    assert set(ids) == {"domain:m.testexample.com"}
    assert ids["domain:m.testexample.com"]["band"] == "unlikely" and ids["domain:m.testexample.com"]["score"] == 0.3
    assert not any(c["band"] in ("confirmed", "probable", "possible") for c in result["candidates"])
    # the Cloudflare name servers are used by the scope, and are a shared provider: not a candidate
    assert "domain:hera.ns.cloudflare.com" not in ids


def test_evaluate_reports_precision_and_recall_for_every_band():
    attribution = {
        "candidates": [
            {"entity_id": "domain:a", "band": "confirmed"},
            {"entity_id": "domain:b", "band": "probable"},
            {"entity_id": "domain:c", "band": "probable"},
            {"entity_id": "domain:d", "band": "possible"},
            {"entity_id": "domain:e", "band": "unlikely"},
        ]
    }
    truth = {"domain:a", "domain:b", "domain:d", "domain:missed"}
    result = evaluate(attribution, truth)
    assert result["confirmed"]["precision"] == 1.0 and result["probable"]["precision"] == 0.5
    assert result["probable"]["or_better_precision"] == round(2 / 3, 4)
    assert result["probable"]["or_better_recall"] == 0.5
    assert result["possible"]["or_better_recall"] == 0.75 and result["unlikely"]["precision"] == 0.0
    assert evaluate({"candidates": []}, truth)["probable"]["precision"] is None
