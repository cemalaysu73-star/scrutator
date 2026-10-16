import pytest
from attrfix import AttrZone
from packfix import provider, write_pack

from scrutator.attribution import signals
from scrutator.attribution.index import Index
from scrutator.attribution.model import SIGNALS
from scrutator.packs import load_packs

PACKS = load_packs()


def base():
    """example.com with its own name server and mail host, on name servers no provider pack knows."""
    zone = AttrZone()
    zone.host("example.com", ["192.0.2.1"])
    zone.name("ns1.example.com")
    zone.name("mail.example.com")
    zone.ns("example.com", ["ns1.tinydns.test", "ns2.tinydns.test"])
    zone.mx("example.com", ["mx.mailhost.test"])
    return zone


def run(extractor, zone, name="partner.test"):
    return extractor(Index(zone.report(PACKS), PACKS), name)


def only(found):
    assert len(found) == 1, found
    return found[0]


# delegation and mail into the scope --------------------------------------------------------------


@pytest.mark.parametrize(
    "extractor, kind",
    [(signals.ns_in_scope, "ns_in_scope"), (signals.mx_in_scope, "mx_in_scope"), (signals.spf_in_scope, "spf_in_scope")],
)
def test_a_candidates_own_records_pointing_into_the_scope_are_strong(extractor, kind):
    zone = base()
    zone.candidate("partner.test")
    evidence = {
        "ns_in_scope": lambda: zone.ns("partner.test", ["ns1.example.com", "ns9.other.test"]),
        "mx_in_scope": lambda: zone.mx("partner.test", ["mail.example.com"]),
        "spf_in_scope": lambda: zone.spf_of("partner.test", "_spf.example.com"),
    }[kind]()
    signal = only(run(extractor, zone))
    assert signal.kind == kind and signal.weight == signal.raw_weight == SIGNALS[kind][0]
    assert signal.evidence_ids == (evidence,) and "example.com" in signal.detail


@pytest.mark.parametrize("extractor", [signals.ns_in_scope, signals.mx_in_scope, signals.spf_in_scope])
def test_records_that_point_elsewhere_or_do_not_exist_are_nothing(extractor):
    zone = base()
    zone.candidate("partner.test")
    zone.ns("partner.test", ["hera.ns.cloudflare.com"])
    zone.mx("partner.test", ["mail.example.com.evil.test"])  # a look-alike, not a name under the scope
    zone.spf_of("partner.test", "_spf.other.test")
    assert run(extractor, zone) == []
    assert run(extractor, zone, "unlooked.test") == []


# certificates ---------------------------------------------------------------------------------------


def test_one_small_fresh_certificate_listing_both_names():
    zone = base()
    zone.candidate("partner.test")
    (evidence,) = zone.cert("example.com", "partner.test", cert_id=42)
    signal = only(run(signals.cert_san, zone))
    assert (signal.weight, signal.note) == (0.6, "")
    assert signal.evidence_ids == (evidence,) and "42" in signal.detail and "2 names" in signal.detail


def test_a_large_certificate_looks_like_a_shared_service_and_counts_for_less():
    zone = base()
    zone.candidate("partner.test")
    others = [f"tenant{n}.test" for n in range(38)]
    zone.cert("example.com", "partner.test", *others)  # 40 names
    signal = only(run(signals.cert_san, zone))
    assert signal.weight == 0.15 and "40 names" in signal.note


def test_a_certificate_long_expired_when_collected_counts_for_half():
    zone = base()
    zone.candidate("partner.test")
    zone.cert("example.com", "partner.test", not_before="2016-07-14T00:00:00", not_after="2017-07-14T23:59:59")
    signal = only(run(signals.cert_san, zone))
    assert signal.weight == 0.3 and "expired" in signal.note


def test_the_strongest_certificate_is_the_one_reported_and_a_certificate_without_scope_is_ignored():
    zone = base()
    zone.candidate("partner.test")
    zone.cert("example.com", "partner.test", *[f"t{n}.test" for n in range(38)], cert_id=1)
    zone.cert("example.com", "partner.test", cert_id=2)
    zone.cert("elsewhere.test", "partner.test", root="elsewhere.test", cert_id=3)
    signal = only(run(signals.cert_san, zone))
    assert signal.weight == 0.6 and "2" in signal.detail
    lonely = AttrZone()
    lonely.host("example.com")
    lonely.candidate("partner.test")
    lonely.cert("elsewhere.test", "partner.test", root="elsewhere.test")
    assert run(signals.cert_san, lonely) == []


# registration ---------------------------------------------------------------------------------------


def test_the_same_registrant_organisation_ties_two_domains_together():
    zone = base()
    zone.candidate("partner.test")
    mine = zone.registrant("example.com", "Example Holdings Ltd")
    theirs = zone.registrant("partner.test", "EXAMPLE HOLDINGS LTD")
    signal = only(run(signals.rdap_registrant, zone))
    assert signal.weight == 0.6 and set(signal.evidence_ids) == {mine, theirs}


def test_different_or_hidden_registrants_tie_nothing():
    zone = base()
    zone.candidate("partner.test")
    zone.registrant("example.com", "Example Holdings Ltd")
    zone.registrant("partner.test", "Partner GmbH")
    assert run(signals.rdap_registrant, zone) == []
    hidden = base()
    hidden.candidate("partner.test")
    hidden.registrant("example.com", "REDACTED FOR PRIVACY")
    hidden.registrant("partner.test", "REDACTED FOR PRIVACY")
    assert run(signals.rdap_registrant, hidden) == []


# name servers, mail, network, use, issuer -------------------------------------------------------------


def test_the_same_unfamiliar_name_servers_count_and_overlap_counts_half_as_much():
    zone = base()
    zone.candidate("partner.test")
    zone.ns("partner.test", ["ns1.tinydns.test", "ns2.tinydns.test"])
    assert only(run(signals.shared_ns, zone)).weight == 0.5
    partial = base()
    partial.candidate("partner.test")
    partial.ns("partner.test", ["ns1.tinydns.test", "ns3.elsewhere.test"])
    signal = only(run(signals.shared_ns, partial))
    assert signal.weight == 0.25 and "overlap" in signal.note


def test_name_servers_of_a_shared_provider_say_nothing_and_say_why():
    zone = AttrZone()
    zone.host("example.com")
    zone.ns("example.com", ["hera.ns.cloudflare.com", "elliott.ns.cloudflare.com"])
    zone.candidate("partner.test")
    zone.ns("partner.test", ["hera.ns.cloudflare.com", "elliott.ns.cloudflare.com"])
    signal = only(run(signals.shared_ns, zone))
    assert signal.weight == 0.0 and signal.raw_weight == 0.5 and "Cloudflare" in signal.note


def test_a_data_entry_for_the_provider_turns_a_signal_into_a_discount(tmp_path):
    zone = base()
    zone.candidate("partner.test")
    zone.ns("partner.test", ["ns1.tinydns.test", "ns2.tinydns.test"])
    extra = load_packs([write_pack(tmp_path, "p.yaml", "providers", [provider("tinydns", provider="TinyDNS", ns=["tinydns.test"])])])
    found = signals.shared_ns(Index(zone.report(extra), extra), "partner.test")
    assert only(found).weight == 0.0 and "TinyDNS" in only(found).note


def test_name_servers_in_the_scope_are_left_to_the_stronger_signal():
    zone = base()
    zone.candidate("partner.test")
    zone.ns("partner.test", ["ns1.example.com"])
    assert run(signals.shared_ns, zone) == []


def test_a_shared_mail_host_counts_unless_it_is_a_mail_provider():
    zone = base()
    zone.candidate("partner.test")
    zone.mx("partner.test", ["mx.mailhost.test"])
    assert only(run(signals.shared_mx, zone)).weight == 0.4
    provider_zone = AttrZone()
    provider_zone.host("example.com")
    provider_zone.mx("example.com", ["aspmx.l.google.com"])
    provider_zone.candidate("partner.test")
    provider_zone.mx("partner.test", ["aspmx.l.google.com"])
    signal = only(run(signals.shared_mx, provider_zone))
    assert signal.weight == 0.0 and "Google Workspace" in signal.note


def network_zone(candidate_asn, scope_asn="AS64500", candidate_owner=None, scope_owner=None):
    zone = AttrZone()
    zone.host("example.com", ["192.0.2.1"])
    zone.announced("192.0.2.1", scope_asn)
    if scope_owner:
        zone.owner("192.0.2.1", scope_owner)
    zone.candidate("partner.test")
    zone.host("partner.test", ["198.51.100.7"], state="candidate")
    zone.announced("198.51.100.7", candidate_asn)
    if candidate_owner:
        zone.owner("198.51.100.7", candidate_owner)
    return zone


def test_the_same_autonomous_system_or_netblock_owner_counts():
    signal = only(run(signals.network_owner, network_zone("AS64500")))
    assert signal.weight == 0.35 and "AS64500" in signal.detail
    by_owner = network_zone("AS64501", scope_asn="AS64500", candidate_owner="Example Net  Holdings", scope_owner="example net holdings")
    assert only(run(signals.network_owner, by_owner)).weight == 0.35
    assert run(signals.network_owner, network_zone("AS64501")) == []


def test_a_cdn_or_hosting_network_is_not_evidence_of_a_common_owner():
    signal = only(run(signals.network_owner, network_zone("AS13335", scope_asn="AS13335")))
    assert signal.weight == 0.0 and "Cloudflare" in signal.note


def test_a_name_the_scope_points_at_is_weak_and_a_provider_is_nothing():
    zone = base()
    zone.candidate("vendor.test")
    zone.spf_of("example.com", "vendor.test")
    signal = only(run(signals.scope_uses, zone, "vendor.test"))
    assert signal.weight == 0.2 and "example.com" in signal.detail
    provider_zone = base()
    provider_zone.outside("sendgrid.net")
    provider_zone.spf_of("example.com", "sendgrid.net")
    found = only(run(signals.scope_uses, provider_zone, "sendgrid.net"))
    assert found.weight == 0.0 and "Twilio SendGrid" in found.note


def test_the_same_private_issuer_counts_a_little_and_a_public_ca_nothing():
    private = "C=ZZ, O=Example Internal, CN=Example Issuing CA"
    zone = base()
    zone.candidate("partner.test")
    zone.cert("example.com", "www.example.com", issuer=private, cert_id=1)
    zone.cert("partner.test", "www.partner.test", root="partner.test", issuer=private, cert_id=2)
    signal = only(run(signals.cert_issuer, zone))
    assert signal.weight == 0.1 and len(signal.evidence_ids) == 2
    public = base()
    public.candidate("partner.test")
    public.cert("example.com", "www.example.com", cert_id=1)
    public.cert("partner.test", "www.partner.test", root="partner.test", cert_id=2)
    found = only(run(signals.cert_issuer, public))
    assert found.weight == 0.0 and "Let's Encrypt" in found.note


def test_one_certificate_for_both_names_is_a_san_signal_not_an_issuer_signal():
    zone = base()
    zone.candidate("partner.test")
    zone.cert("example.com", "partner.test", issuer="C=ZZ, O=Example Internal, CN=Example Issuing CA")
    assert run(signals.cert_issuer, zone) == []


def test_every_signal_for_a_name_is_returned_strongest_first_with_evidence():
    zone = base()
    zone.candidate("partner.test")
    zone.ns("partner.test", ["ns1.example.com"])
    zone.cert("example.com", "partner.test")
    zone.mx("partner.test", ["mx.mailhost.test"])
    found = signals.signals_for(Index(zone.report(PACKS), PACKS), "partner.test")
    assert [s.kind for s in found] == ["ns_in_scope", "cert_san", "shared_mx"]
    assert all(s.evidence_ids and s.detail for s in found)
    assert signals.signals_for(Index(zone.report(PACKS), PACKS), "nobody.test") == []
