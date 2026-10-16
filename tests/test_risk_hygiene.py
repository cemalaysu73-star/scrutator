from datetime import datetime, timedelta, timezone

from packfix import takeover, write_pack
from riskfix import COLLECTED, Zone

from scrutator.packs import load_packs
from scrutator.risk.hygiene import (
    caa_gaps,
    dangling_cnames,
    dmarc_gaps,
    domain_expiry,
    forgotten_names,
    spf_weaknesses,
)
from scrutator.risk.view import View

PACKS = load_packs()


def run(rule, zone, packs=PACKS):
    return rule(View(zone.report(packs), packs))


def ids(risks):
    return [(r.rule_id, r.entity_ids[0]) for r in risks]


# dangling CNAME -------------------------------------------------------------------------


def test_a_cname_to_a_missing_claimable_azure_host_is_high():
    z = Zone()
    z.cname("shop.example.com", "shop-demo.azurewebsites.net")
    (risk,) = run(dangling_cnames, z)
    assert (risk.rule_id, risk.severity.value, risk.confidence.value) == ("dangling-cname-claimable", "high", "high")
    assert risk.entity_ids == ("domain:shop.example.com", "domain:shop-demo.azurewebsites.net")
    assert "NXDOMAIN" in risk.explanation and "microsoft-azure" in risk.explanation
    a, cname = (z.dns("A", "shop.example.com", "NXDOMAIN"), z.dns("CNAME", "shop.example.com", ["shop-demo.azurewebsites.net."]))
    assert risk.evidence_ids == (a, cname)


def test_a_service_that_needs_an_active_check_is_medium():
    z = Zone()
    z.cname("docs.example.com", "team.bitbucket.io")
    (risk,) = run(dangling_cnames, z)
    assert (risk.rule_id, risk.severity.value) == ("dangling-cname-known-service", "medium")


def test_an_unrecognised_dangling_target_is_medium_and_says_only_what_is_known():
    z = Zone()
    z.cname("old.example.com", "legacy.example.net")
    (risk,) = run(dangling_cnames, z)
    assert (risk.rule_id, risk.severity.value) == ("dangling-cname", "medium")
    assert "takeover" not in risk.explanation


def test_an_alias_that_resolves_or_has_no_negative_evidence_is_not_dangling():
    z = Zone()
    z.cname("live.example.com", "demo.azurewebsites.net", address=["192.0.2.30"])
    z.cname("empty.example.com", "demo.azurewebsites.net", address="NODATA")
    z.name("untested.example.com")
    z.dns("CNAME", "untested.example.com", ["demo.azurewebsites.net."])  # the A lookup left no evidence
    assert run(dangling_cnames, z) == []


def test_a_chain_inside_the_scope_is_reported_once_at_its_end():
    z = Zone()
    z.name("back.example.com")
    z.cname("front.example.com", "back.example.com")
    z.dns("CNAME", "back.example.com", ["gone.example.net."])
    z.dns("A", "back.example.com", "NXDOMAIN")
    assert ids(run(dangling_cnames, z)) == [("dangling-cname", "domain:back.example.com")]


def test_a_data_entry_in_a_user_pack_changes_the_verdict_without_any_code_change(tmp_path):
    z = Zone()
    z.cname("pages.example.com", "demo.pages.example.net")
    assert ids(run(dangling_cnames, z)) == [("dangling-cname", "domain:pages.example.com")]
    write_pack(tmp_path / "mine", "t.yaml", "takeover", [takeover(cname=["pages.example.net"])])
    packs = load_packs([tmp_path / "mine"])
    assert ids(run(dangling_cnames, z, packs)) == [("dangling-cname-claimable", "domain:pages.example.com")]


# SPF --------------------------------------------------------------------------------------


def spf_rules(*texts):
    z = Zone()
    z.txt("example.com", *texts)
    return [r.rule_id for r in run(spf_weaknesses, z)]


def test_the_ending_of_an_spf_record_decides_its_rating():
    assert spf_rules("v=spf1 include:spf.dns.example.net +all") == ["spf-allows-all"]
    assert spf_rules("v=spf1 mx all") == ["spf-allows-all"]
    assert spf_rules("v=spf1 mx ?all") == ["spf-neutral-all"]
    assert spf_rules("v=spf1 mx ~all") == ["spf-softfail-all"]
    assert spf_rules("v=spf1 mx -all") == []
    assert spf_rules("v=spf1 mx") == ["spf-no-all"]
    assert spf_rules("v=spf1 redirect=_spf.example.net") == []


def test_severities_follow_the_catalog():
    z = Zone()
    z.txt("example.com", "v=spf1 +all")
    z.txt("mail.example.com", "v=spf1 ~all")
    risks = {r.entity_ids[0]: r for r in run(spf_weaknesses, z)}
    assert risks["domain:example.com"].severity.value == "high"
    assert risks["domain:mail.example.com"].severity.value == "low"
    assert "+all" in risks["domain:example.com"].explanation


def test_two_spf_records_are_one_finding_and_other_txt_records_are_ignored():
    assert spf_rules("v=spf1 -all", "v=spf1 +all") == ["spf-multiple-records"]
    assert spf_rules("google-site-verification=abc") == []
    assert spf_rules("v=spf1 -all", "google-site-verification=abc") == []


def test_only_the_records_own_lookup_terms_are_counted_against_the_limit_of_ten():
    includes = " ".join(f"include:s{n}.example.net" for n in range(10))
    assert spf_rules(f"v=spf1 {includes} -all") == []
    assert spf_rules(f"v=spf1 {includes} include:s10.example.net -all") == ["spf-too-many-lookups"]
    mixed = "v=spf1 a mx ptr exists:%{i}.example.net include:a.example.net include:b.example.net include:c.example.net include:d.example.net include:e.example.net redirect=x.example.net ip4:192.0.2.0/24 -all"
    assert spf_rules(mixed) == []  # eleven terms would be too many, ten is the limit: a, mx, ptr, exists, 5 includes, redirect = 10
    assert spf_rules(mixed.replace(" ip4:", " a:b.example.net ip4:")) == ["spf-too-many-lookups"]


def test_a_long_spf_record_in_several_quoted_chunks_is_read_whole():
    z = Zone()
    z.name("example.com")
    z.dns("TXT", "example.com", ['"v=spf1 include:a.example.net " "+all"'])
    assert [r.rule_id for r in run(spf_weaknesses, z)] == ["spf-allows-all"]


# DMARC ------------------------------------------------------------------------------------


def mail_zone(dmarc):
    """example.com with mail; `dmarc` is what the _dmarc lookup returned."""
    z = Zone()
    mx = z.mx("example.com", ["mx1.example.net"])
    own = z.dns("TXT", "_dmarc.example.com", dmarc)
    return z, mx, own


def test_a_mail_domain_without_dmarc_cites_the_mx_and_the_absence():
    for result in ("NXDOMAIN", "NODATA"):
        z, mx, own = mail_zone(result)
        (risk,) = run(dmarc_gaps, z)
        assert risk.rule_id == "dmarc-missing" and risk.evidence_ids == (mx, own)
        assert risk.severity.value == "medium"


def test_a_txt_record_at_dmarc_that_is_not_dmarc_still_counts_as_missing():
    z, mx, own = mail_zone(['"hello"'])
    assert ids(run(dmarc_gaps, z)) == [("dmarc-missing", "domain:example.com")]


def test_a_policy_of_none_is_monitoring_only_and_an_enforced_policy_is_fine():
    z, *_ = mail_zone(['"v=DMARC1; p=none; rua=mailto:dmarc@example.com"'])
    assert ids(run(dmarc_gaps, z)) == [("dmarc-monitoring-only", "domain:example.com")]
    z, *_ = mail_zone(['"v=DMARC1; p=reject"'])
    assert run(dmarc_gaps, z) == []
    z, *_ = mail_zone(['"v=DMARC1; p=quarantine; pct=100"'])
    assert run(dmarc_gaps, z) == []


def test_no_mail_and_no_evidence_mean_no_finding():
    z = Zone()
    z.name("example.com")
    z.dns("TXT", "_dmarc.example.com", "NXDOMAIN")  # no MX at all
    z.name("null.example.com")
    z.dns("MX", "null.example.com", ["0 ."])  # a null MX says "no mail here"
    z.dns("TXT", "_dmarc.null.example.com", "NXDOMAIN")
    z.mx("mail.example.com", ["mx1.example.net"])  # mail, but the lookup left no evidence
    assert run(dmarc_gaps, z) == []


def test_a_parent_domains_dmarc_record_covers_a_subdomain_with_mail():
    z = Zone()
    z.name("example.com")
    z.dns("TXT", "_dmarc.example.com", ['"v=DMARC1; p=reject"'])
    z.mx("mail.example.com", ["mx1.example.net"])
    z.dns("TXT", "_dmarc.mail.example.com", "NXDOMAIN")
    assert run(dmarc_gaps, z) == []
    bare = Zone()
    bare.name("example.com")
    bare.dns("TXT", "_dmarc.example.com", "NXDOMAIN")
    bare.mx("mail.example.com", ["mx1.example.net"])
    bare.dns("TXT", "_dmarc.mail.example.com", "NXDOMAIN")
    assert ids(run(dmarc_gaps, bare)) == [("dmarc-missing", "domain:mail.example.com")]


# CAA --------------------------------------------------------------------------------------


def test_a_zone_apex_without_caa_is_flagged_and_one_with_caa_is_not():
    z = Zone()
    ns = z.ns("example.com", ["ns1.dns.example.net"])
    caa = z.dns("CAA", "example.com", "NODATA")
    (risk,) = run(caa_gaps, z)
    assert risk.rule_id == "caa-missing" and risk.evidence_ids == (caa, ns) and risk.severity.value == "low"
    z = Zone()
    z.ns("example.com", ["ns1.dns.example.net"])
    z.dns("CAA", "example.com", ['0 issue "letsencrypt.org"'])
    assert run(caa_gaps, z) == []


def test_without_a_caa_lookup_there_is_no_finding_and_a_parent_zone_caa_covers_a_child_zone():
    z = Zone()
    z.ns("example.com", ["ns1.dns.example.net"])
    assert run(caa_gaps, z) == []
    z = Zone()
    z.ns("example.com", ["ns1.dns.example.net"])
    z.dns("CAA", "example.com", ['0 issue "letsencrypt.org"'])
    z.ns("eu.example.com", ["ns1.dns.example.net"])
    z.dns("CAA", "eu.example.com", "NODATA")
    assert run(caa_gaps, z) == []


# domain expiry ----------------------------------------------------------------------------


def expiry_rule(days):
    collected = datetime.fromisoformat(COLLECTED)
    z = Zone()
    z.name("example.com")
    z.rdap("example.com", (collected + timedelta(days=days)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    return [(r.rule_id, r.severity.value) for r in run(domain_expiry, z)]


def test_expiry_is_judged_against_the_time_the_data_was_collected():
    assert expiry_rule(-3) == [("domain-expired", "high")]
    assert expiry_rule(10) == [("domain-expiring", "high")]
    assert expiry_rule(20) == [("domain-expiring", "medium")]
    assert expiry_rule(31) == []
    assert expiry_rule(300) == []


def test_unreadable_rdap_dates_are_ignored():
    z = Zone()
    z.name("example.com")
    z.rdap("example.com", "soon")
    assert run(domain_expiry, z) == []


def test_the_real_example_com_registration_is_not_flagged():
    z = Zone()
    z.name("example.com")
    z.rdap("example.com", "2027-08-13T04:00:00Z")
    assert run(domain_expiry, z) == []


# forgotten-looking names ----------------------------------------------------------------------


def test_a_dev_or_staging_name_that_resolves_is_flagged_with_low_confidence():
    z = Zone()
    z.host("dev.example.com", ["192.0.2.50"])
    z.host("staging-api2.example.com", ["192.0.2.51"])
    z.host("www.example.com", ["192.0.2.52"])
    z.host("devon.example.com", ["192.0.2.53"])
    risks = run(forgotten_names, z)
    assert [(r.entity_ids[0], r.confidence.value) for r in risks] == [
        ("domain:dev.example.com", "low"),
        ("domain:staging-api2.example.com", "low"),
    ]
    assert "192.0.2.50" in risks[0].explanation


def test_a_forgotten_looking_name_that_does_not_resolve_is_not_flagged_here():
    z = Zone()
    z.name("dev.example.com")
    z.dns("A", "dev.example.com", "NXDOMAIN")
    assert run(forgotten_names, z) == []


def test_the_registered_domain_itself_never_counts():
    z = Zone(domains=("test.com",))
    z.host("test.com", ["192.0.2.60"])
    z.host("www.test.com", ["192.0.2.61"])
    assert run(forgotten_names, z) == []
