from riskfix import Zone

from scrutator.packs import load_packs
from scrutator.risk.view import View, parse_time, txt_values

PACKS = load_packs()


def view(zone):
    return View(zone.report(PACKS), PACKS)


def test_only_in_scope_domains_count_as_names():
    z = Zone()
    z.host("www.example.com")
    z.name("cdn.example.net", "out")
    z.entity("ip", "192.0.2.10", "linked")
    assert view(z).names == {"www.example.com"}


def test_an_entity_marked_in_scope_but_outside_the_recorded_scope_is_not_trusted():
    z = Zone()
    z.name("www.example.com")
    z.name("www.example.org")  # claims state "in" but the scope does not cover it
    assert view(z).names == {"www.example.com"}


def test_dns_evidence_is_indexed_by_type_and_name_and_only_for_in_scope_names():
    z = Zone()
    z.host("www.example.com", ["192.0.2.10", "192.0.2.11"])
    z.dns("A", "outside.example.org", "NXDOMAIN")
    v = view(z)
    assert v.answers("A", "www.example.com") == ["192.0.2.10", "192.0.2.11"]
    assert v.dns("A", "outside.example.org") is None
    assert v.status("A", "nope.example.com") is None


def test_negative_results_are_read_back_from_their_payload():
    z = Zone()
    z.name("ghost.example.com")
    z.dns("A", "ghost.example.com", "NXDOMAIN")
    z.dns("CAA", "ghost.example.com", "NODATA")
    v = view(z)
    assert v.status("A", "ghost.example.com") == "nxdomain"
    assert v.status("CAA", "ghost.example.com") == "nodata"
    assert v.answers("A", "ghost.example.com") == []


def test_dmarc_names_are_accepted_under_in_scope_names_only():
    z = Zone()
    z.name("example.com")
    z.dns("TXT", "_dmarc.example.com", "NXDOMAIN")
    z.dns("TXT", "_dmarc.example.org", "NXDOMAIN")
    v = view(z)
    assert v.status("TXT", "_dmarc.example.com") == "nxdomain"
    assert v.dns("TXT", "_dmarc.example.org") is None


def test_targets_skip_the_null_mx_and_strip_the_trailing_dot():
    z = Zone()
    z.name("example.com")
    z.dns("MX", "example.com", ["0 ."])
    z.name("mail.example.com")
    z.dns("MX", "mail.example.com", ["10 Mx1.Example.NET.", "20 mx2.example.net."])
    v = view(z)
    assert v.targets("MX", "example.com") == []
    assert v.targets("MX", "mail.example.com") == ["mx1.example.net", "mx2.example.net"]


def test_txt_values_join_the_chunks_of_a_long_record():
    assert txt_values(['"v=spf1 include:a.example.net " "-all"', '"plain"', "bare"]) == ["v=spf1 include:a.example.net -all", "plain", "bare"]


def test_times_with_and_without_a_zone_designator_compare():
    assert parse_time("2027-08-13T04:00:00Z") == parse_time("2027-08-13T04:00:00+00:00") == parse_time("2027-08-13T04:00:00")
    assert parse_time("2027-08-13T06:00:00+02:00") == parse_time("2027-08-13T04:00:00")
    assert parse_time("not a time") is None


def test_the_longest_zone_contains_a_name():
    z = Zone()
    z.ns("example.com", ["ns1.dns.example.net"])
    z.ns("eu.example.com", ["ns1.dns.example.net"])
    z.name("www.eu.example.com")
    z.name("www.example.com")
    v = view(z)
    zones = v.zone_apexes()
    assert zones == ["eu.example.com", "example.com"]
    assert v.zone_of("www.eu.example.com", zones) == "eu.example.com"
    assert v.zone_of("www.example.com", zones) == "example.com"
    assert v.zone_of("elsewhere.example.org", zones) is None


def test_naming_sources_are_found_through_the_relations():
    z = Zone()
    crt = z.found("dev.example.com", "crtsh")
    way = z.found("dev.example.com", "wayback")
    z.found("www.example.com", "crtsh")
    named = view(z).named_by()
    assert named["dev.example.com"] == sorted([("crtsh", crt), ("wayback", way)])
    assert set(named) == {"dev.example.com", "www.example.com"}


def test_rdap_records_are_indexed_for_in_scope_domains_only():
    z = Zone()
    z.name("example.com")
    rid = z.rdap("example.com", "2027-08-13T04:00:00Z", ["ns1.dns.example.net"])
    z.rdap("example.org", "2027-08-13T04:00:00Z")
    v = view(z)
    assert set(v.rdap) == {"example.com"} and v.rdap["example.com"]["evidence_id"] == rid
