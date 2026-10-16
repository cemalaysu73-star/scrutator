import json

import pytest
from attrfix import AttrZone

from scrutator.attribution.index import Index
from scrutator.attribution.model import BANDS, OWNERSHIP, POSSIBLE_AT, PROBABLE_AT, SIGNALS, Signal, band_for, band_rank, combine
from scrutator.packs import load_packs

PACKS = load_packs()


def index(zone):
    return Index(zone.report(PACKS), PACKS)


def test_combining_signals_never_passes_one_and_weak_ones_stay_weak():
    assert combine([]) == 0.0
    assert combine([0.5]) == 0.5
    assert combine([0.5, 0.5]) == 0.75
    assert combine([0.9, 0.6]) == 0.96
    assert combine([0.1] * 5) < 0.45
    assert combine([0.9, 0.9, 0.9]) < 1.0


def test_a_single_observation_cannot_confirm_anything():
    assert band_for(0.97, {"ns_in_scope"}) == "probable"
    assert band_for(0.97, {"ns_in_scope", "cert_san"}) == "confirmed"
    assert band_for(PROBABLE_AT, {"mx_in_scope"}) == "probable" and band_for(PROBABLE_AT - 0.001, {"mx_in_scope"}) == "possible"
    assert band_for(POSSIBLE_AT, {"cert_san"}) == "possible" and band_for(POSSIBLE_AT - 0.001, {"cert_san"}) == "unlikely"
    assert [band_rank(b) for b in BANDS] == [3, 2, 1, 0]


def test_evidence_a_partner_or_a_host_could_share_never_gets_past_possible():
    shared = {"cert_san", "shared_ns", "shared_mx", "network_owner"}
    assert band_for(combine([0.6, 0.5, 0.4, 0.35]), shared) == "possible"
    assert band_for(combine([0.6, 0.5, 0.4, 0.35]), shared | {"rdap_registrant"}) == "confirmed"
    assert OWNERSHIP == {"ns_in_scope", "mx_in_scope", "spf_in_scope", "rdap_registrant"} and OWNERSHIP <= set(SIGNALS)


def test_every_signal_kind_has_a_weight_below_one_and_a_description():
    assert all(0 < weight < 1 and text for weight, text in SIGNALS.values())
    assert Signal("cert_san", 0.6, 0.6, "d", ("e",)).to_dict()["evidence_ids"] == ["e"]


def test_scope_is_decided_by_the_policy_not_only_by_the_entities_seen():
    zone = AttrZone()
    zone.host("www.example.com")
    zone.candidate("partner.test")
    zone.outside("cdn.other.net")
    view = index(zone)
    assert view.names == {"www.example.com"}
    assert view.in_scope("anything.example.com") and view.in_scope("EXAMPLE.com.")
    assert not view.in_scope("partner.test") and not view.in_scope("example.com.evil.test")
    assert view.universe() == ["cdn.other.net", "partner.test"]


def test_a_name_promoted_after_the_scan_stays_in_the_universe():
    zone = AttrZone()
    zone.host("www.example.com")
    zone.name("partner.test", "in")  # promoted to in, but the recorded scope does not cover it
    assert index(zone).universe() == ["partner.test"]


def test_dns_answers_are_read_for_any_name_including_candidates():
    zone = AttrZone()
    zone.candidate("partner.test")
    ns_id = zone.ns("partner.test", ["ns1.example.com", "ns2.example.com"])
    zone.mx("partner.test", ["mail.example.com"])
    zone.spf_of("partner.test", "_spf.example.com", "mail.other.net")
    view = index(zone)
    assert view.targets("NS", "partner.test") == (["ns1.example.com", "ns2.example.com"], ns_id)
    assert view.targets("MX", "partner.test")[0] == ["mail.example.com"]
    assert view.spf_targets("partner.test")[0] == ["_spf.example.com", "mail.other.net"]
    assert view.targets("NS", "missing.test") is None and view.spf_targets("missing.test") is None


def test_a_negative_or_empty_answer_has_no_targets():
    zone = AttrZone()
    zone.name("gone.example.com")
    zone.dns("NS", "gone.example.com", "NXDOMAIN")
    zone.dns("MX", "gone.example.com", ["0 ."])  # a null MX
    view = index(zone)
    assert view.targets("NS", "gone.example.com") is None
    assert view.targets("MX", "gone.example.com") is None


def test_certificates_are_parsed_with_every_name_on_them():
    zone = AttrZone()
    zone.candidate("partner.test")
    zone.cert("example.com", "*.example.com", "partner.test", "WWW.Partner.Test", cert_id=7)
    view = index(zone)
    certs = view.certs_naming("partner.test")
    assert certs and certs[0].cert_id == "7"
    assert certs[0].names == ("example.com", "partner.test", "www.partner.test")  # wildcard prefix removed, lower case, sorted
    assert view.certs_naming("nobody.test") == []


def test_unreadable_certificate_payloads_are_ignored():
    zone = AttrZone()
    zone.ev("crtsh", "GET https://crt.sh/?q=%25.example.com&output=json", "not json")
    zone.ev("crtsh", "GET https://crt.sh/?q=%25.example.com&output=json&x=1", json.dumps({"not": "a list"}))
    zone.ev("crtsh", "GET https://crt.sh/?q=%25.example.com&output=json&x=2", json.dumps(["text", {"name_value": "bad name!"}]))
    assert index(zone).certs == []


def test_expiry_is_measured_against_the_moment_of_collection():
    zone = AttrZone()
    zone.candidate("old.test")
    zone.cert("example.com", "old.test", not_before="2016-07-14T00:00:00", not_after="2017-07-14T23:59:59")
    zone.cert("example.com", "fresh.test", cert_id=2)
    view = index(zone)
    assert view.expired_days(view.certs_naming("old.test")[0]) > 365 * 8
    assert view.expired_days(view.certs_naming("fresh.test")[0]) < 0
    broken = view.certs_naming("fresh.test")[0]
    assert view.expired_days(type(broken)(broken.evidence_id, "1", "", ("a",), "", "not a date", broken.collected_at)) is None


def test_registrants_drop_placeholders_and_keep_their_evidence():
    zone = AttrZone()
    zone.name("example.com")
    good = zone.registrant("example.com", "Example Holdings Ltd")
    zone.candidate("partner.test")
    zone.registrant("partner.test", "REDACTED FOR PRIVACY")
    view = index(zone)
    assert view.registrants("example.com") == [("Example Holdings Ltd", (good,))]
    assert view.registrants("partner.test") == []


def test_addresses_and_networks_follow_the_relations():
    zone = AttrZone()
    zone.host("www.example.com", addresses=["192.0.2.10"])
    zone.announced("192.0.2.10", "AS64500")
    zone.owner("192.0.2.10", "EXAMPLE-NET  Holdings")
    view = index(zone)
    ((ip, evidence),) = view.addresses("www.example.com")
    assert ip == "192.0.2.10" and evidence
    kinds = {(kind, value) for kind, value, _ in view.networks("192.0.2.10")}
    assert kinds == {("asn", "AS64500"), ("owner", "example-net holdings")}
    assert view.addresses("nobody.example.com") == [] and view.networks("203.0.113.1") == []


@pytest.mark.parametrize("scope", [None])
def test_a_report_without_a_recorded_scope_falls_back_to_the_names_it_holds(scope):
    zone = AttrZone()
    zone.host("www.example.com")
    report = zone.report(PACKS)
    report["scope"] = scope
    view = Index(report, PACKS)
    assert view.in_scope("www.example.com") and not view.in_scope("partner.test")
