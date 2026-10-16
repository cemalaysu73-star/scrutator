from packfix import provider, write_pack
from riskfix import Zone

from scrutator.packs import load_packs
from scrutator.risk.dependency import build_dependency_map
from scrutator.risk.view import View

PACKS = load_packs()


def deps(zone):
    return build_dependency_map(View(zone.report(PACKS), PACKS))


def only(items, category, provider):
    (found,) = [d for d in items.of(category) if d.provider == provider]
    return found


def test_dns_provider_comes_from_the_ns_records_and_covers_every_name_in_the_zone():
    z = Zone()
    ns = z.ns("example.com", ["hera.ns.cloudflare.com", "elliott.ns.cloudflare.com"])
    z.host("www.example.com")
    z.host("api.example.com")
    d = only(deps(z), "dns", "Cloudflare")
    assert d.hostnames == {"example.com", "www.example.com", "api.example.com"}
    assert d.via == {"ns"} and d.evidence_ids == {ns}
    assert d.verified is True


def test_unrecognised_name_servers_are_listed_as_unmatched_not_guessed():
    z = Zone()
    z.ns("example.com", ["hera.ns.cloudflare.com", "ns1.homegrown.example.net"])
    items = deps(z)
    assert items.unmatched_ns == {"example.com": ["ns1.homegrown.example.net"]}


def test_mail_provider_comes_from_mx_targets_and_spf_includes():
    z = Zone()
    mx = z.mx("example.com", ["example-com.mail.protection.outlook.com"])
    txt = z.txt("example.com", "v=spf1 include:spf.protection.outlook.com include:_spf.google.com -all")
    items = deps(z)
    microsoft = only(items, "mail", "Microsoft 365")
    assert microsoft.via == {"mx", "spf"} and microsoft.evidence_ids == {mx, txt}
    assert only(items, "mail", "Google Workspace").via == {"spf"}


def test_a_null_mx_is_not_a_mail_dependency():
    z = Zone()
    z.name("example.com")
    z.dns("MX", "example.com", ["0 ."])
    assert deps(z).of("mail") == []


def test_hosting_comes_from_cname_targets_and_the_as_behind_the_addresses():
    z = Zone()
    z.cname("app.example.com", "demo.herokuapp.com", address=["192.0.2.30"])
    z.host("www.example.com", ["198.51.100.7"])
    announce = z.announced("198.51.100.7", "AS13335")
    items = deps(z)
    assert only(items, "hosting", "Heroku").hostnames == {"app.example.com"}
    cloudflare = only(items, "cdn", "Cloudflare")
    assert cloudflare.hostnames == {"www.example.com"} and cloudflare.via == {"asn"}
    assert announce in cloudflare.evidence_ids


def test_the_certificate_authority_counts_only_certificates_valid_when_collected():
    z = Zone()
    live = z.found("www.example.com", issuer="C=US, O=Let's Encrypt, CN=R3", not_before="2026-09-01T00:00:00", not_after="2026-12-01T00:00:00")
    z.found("old.example.com", issuer="C=US, O=DigiCert Inc, CN=Old CA", not_before="2016-01-01T00:00:00", not_after="2018-01-01T00:00:00")
    z.found("odd.example.com", issuer="C=XX, O=Nobody Known, CN=Mystery CA")
    items = deps(z)
    ca = only(items, "ca", "Let's Encrypt")
    assert ca.hostnames == {"www.example.com"} and live in ca.evidence_ids
    assert [d.provider for d in items.of("ca")] == ["Let's Encrypt"]


def test_out_of_scope_names_contribute_nothing():
    z = Zone()
    z.name("www.example.org")
    z.dns("CNAME", "www.example.org", ["demo.herokuapp.com."])
    assert deps(z).of("dns", "mail", "cdn", "hosting", "ca") == []


def test_the_list_form_is_sorted_and_plain():
    z = Zone()
    z.ns("example.com", ["hera.ns.cloudflare.com"])
    z.mx("example.com", ["example-com.mail.protection.outlook.com"])
    listed = deps(z).to_list()
    assert [(d["category"], d["provider"]) for d in listed] == [("dns", "Cloudflare"), ("mail", "Microsoft 365")]
    assert listed[0]["hostnames"] == ["example.com"] and isinstance(listed[0]["evidence_ids"], list)


def test_adding_a_provider_is_one_data_entry_and_changes_the_map_without_any_code_change(tmp_path):
    z = Zone()
    z.ns("example.com", ["ns1.dns.example.net", "ns2.dns.example.net"])
    z.host("www.example.com")
    before = build_dependency_map(View(z.report(PACKS), PACKS))
    assert before.of("dns") == [] and before.unmatched_ns == {"example.com": ["ns1.dns.example.net", "ns2.dns.example.net"]}

    write_pack(tmp_path / "mine", "mine.yaml", "providers", [provider("example-dns", provider="Example DNS", ns=["dns.example.net"])])
    packs = load_packs([tmp_path / "mine"])
    after = build_dependency_map(View(z.report(packs), packs))
    (dns,) = after.of("dns")
    assert (dns.provider, dns.hostnames, after.unmatched_ns) == ("Example DNS", {"example.com", "www.example.com"}, {})
    assert after.to_list()[0]["verified"] is True
