from riskfix import Zone

from scrutator.packs import load_packs
from scrutator.risk.analyst import ghost_hostnames, numbering_gaps, source_disagreement
from scrutator.risk.view import View

PACKS = load_packs()


def run(rule, zone):
    return rule(View(zone.report(PACKS), PACKS))


# ghost hostnames --------------------------------------------------------------------------


def test_a_certificate_name_that_dns_does_not_know_is_a_ghost():
    z = Zone()
    cert = z.found("dev.example.com", "crtsh")
    z.dns("A", "dev.example.com", "NXDOMAIN")
    (risk,) = run(ghost_hostnames, z)
    assert (risk.rule_id, risk.category, risk.severity.value, risk.confidence.value) == ("ghost-hostname", "analyst", "info", "low")
    assert risk.evidence_ids == (cert, z.dns("A", "dev.example.com", "NXDOMAIN"))
    assert "crtsh" in risk.explanation and "NXDOMAIN" in risk.explanation


def test_two_independent_sources_raise_the_confidence():
    z = Zone()
    z.found("old.example.com", "crtsh")
    z.found("old.example.com", "wayback")
    z.dns("A", "old.example.com", "NXDOMAIN")
    (risk,) = run(ghost_hostnames, z)
    assert risk.confidence.value == "medium" and len(risk.evidence_ids) == 3


def test_a_named_host_that_resolves_or_was_never_looked_up_is_not_a_ghost():
    z = Zone()
    z.found("www.example.com", "crtsh")
    z.host("www.example.com")
    z.found("untested.example.com", "crtsh")  # DNS never ran for it: no evidence of absence
    z.found("nodata.example.com", "crtsh")
    z.dns("A", "nodata.example.com", "NODATA")
    assert run(ghost_hostnames, z) == []


def test_an_alias_to_nowhere_is_left_to_the_cname_rule():
    z = Zone()
    z.found("shop.example.com", "crtsh")
    z.cname("shop.example.com", "gone.example.net")
    assert run(ghost_hostnames, z) == []


def test_a_name_outside_the_scope_is_never_a_ghost():
    z = Zone()
    z.found("dev.example.org", "crtsh")
    z.dns("A", "dev.example.org", "NXDOMAIN")
    assert run(ghost_hostnames, z) == []


# numbering gaps ---------------------------------------------------------------------------


def named(z, *labels, suffix="example.com"):
    for label in labels:
        z.found(f"{label}.{suffix}", "crtsh")


def test_a_missing_number_in_a_series_is_reported_with_the_names_that_exist():
    z = Zone()
    named(z, "app1", "app2", "app4")
    (risk,) = run(numbering_gaps, z)
    assert (risk.rule_id, risk.category) == ("numbering-gap", "analyst")
    assert risk.entity_ids == ("domain:app1.example.com", "domain:app2.example.com", "domain:app4.example.com")
    assert "app3.example.com" in risk.explanation and len(risk.evidence_ids) == 3  # one citation per name that exists


def test_zero_padded_numbers_keep_their_width():
    z = Zone()
    named(z, "web01", "web02", "web05")
    (risk,) = run(numbering_gaps, z)
    assert "web03.example.com" in risk.explanation


def test_complete_short_or_far_apart_series_are_not_reported():
    z = Zone()
    named(z, "a1", "a2", "a3")  # complete
    named(z, "b1", "b3")  # only two names
    named(z, "c1", "c2", "c900")  # not a series
    named(z, "d1", "d2", "d4", suffix="example.net")  # out of scope
    assert run(numbering_gaps, z) == []


def test_series_under_different_parents_are_separate():
    z = Zone()
    named(z, "app1", "app2", "app3")
    named(z, "app5", suffix="eu.example.com")
    assert run(numbering_gaps, z) == []


# source disagreement ----------------------------------------------------------------------


def test_registry_and_zone_name_servers_that_differ_are_reported():
    z = Zone()
    ns = z.ns("example.com", ["ns1.dns.example.net", "ns2.dns.example.net"])
    rdap = z.rdap("example.com", "2027-08-13T04:00:00Z", ["NS1.DNS.EXAMPLE.NET", "NS9.OLD.EXAMPLE.NET"])
    (risk,) = run(source_disagreement, z)
    assert (risk.rule_id, risk.category, risk.severity.value) == ("source-disagreement", "analyst", "low")
    assert risk.evidence_ids == (rdap, ns)
    assert "ns9.old.example.net" in risk.explanation and "ns2.dns.example.net" in risk.explanation


def test_matching_sets_in_any_case_and_order_are_not_a_disagreement():
    z = Zone()
    z.ns("example.com", ["hera.ns.cloudflare.com", "elliott.ns.cloudflare.com"])
    z.rdap("example.com", "2027-08-13T04:00:00Z", ["ELLIOTT.NS.CLOUDFLARE.COM", "HERA.NS.CLOUDFLARE.COM"])
    assert run(source_disagreement, z) == []


def test_one_missing_side_is_not_a_disagreement():
    z = Zone()
    z.rdap("example.com", "2027-08-13T04:00:00Z", ["ns1.dns.example.net"])  # DNS side unknown
    z.ns("example.org", ["ns1.dns.example.net"])
    z.name("example.com")
    assert run(source_disagreement, z) == []
