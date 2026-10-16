from riskfix import Zone

from scrutator.packs import load_packs
from scrutator.risk.concentration import concentration_risks
from scrutator.risk.view import View

PACKS = load_packs()


def run(zone):
    return concentration_risks(View(zone.report(PACKS), PACKS))


def rules(risks):
    return [(r.rule_id, r.severity.value) for r in risks]


def test_one_dns_provider_for_every_zone_is_reported_with_the_number_of_names():
    z = Zone()
    ns = z.ns("example.com", ["hera.ns.cloudflare.com", "elliott.ns.cloudflare.com"])
    z.host("www.example.com")
    z.host("api.example.com")
    (risk,) = run(z)
    assert rules([risk]) == [("concentration-dns", "info")]
    assert risk.evidence_ids == (ns,) and risk.entity_ids == ("domain:example.com",)
    assert "Cloudflare" in risk.explanation and "3 in-scope name(s)" in risk.explanation


def test_the_rating_rises_when_ten_or_more_names_depend_on_the_provider():
    z = Zone()
    z.ns("example.com", ["hera.ns.cloudflare.com"])
    for n in range(10):
        z.host(f"h{n}.example.com", [f"192.0.2.{n + 1}"])
    assert rules(run(z)) == [("concentration-dns", "low")]


def test_two_dns_providers_or_an_unrecognised_name_server_mean_no_claim():
    z = Zone()
    z.ns("example.com", ["hera.ns.cloudflare.com", "ns-2048.awsdns-64.com"])
    assert run(z) == []
    z = Zone()
    z.ns("example.com", ["hera.ns.cloudflare.com", "ns1.homegrown.example.net"])
    assert run(z) == []


def test_one_mail_provider_is_a_dependency_not_a_risk():
    z = Zone()
    z.mx("example.com", ["example-com.mail.protection.outlook.com"])
    z.mx("sales.example.com", ["sales-example-com.mail.protection.outlook.com"])
    assert run(z) == []


def test_three_names_on_one_cdn_or_host_are_reported_two_are_not():
    z = Zone()
    for n in range(3):
        z.cname(f"app{n}.example.com", f"demo{n}.herokuapp.com", address=[f"192.0.2.{n + 1}"])
    (risk,) = run(z)
    assert rules([risk]) == [("concentration-edge", "info")] and "Heroku" in risk.explanation
    z = Zone()
    for n in range(2):
        z.cname(f"app{n}.example.com", f"demo{n}.herokuapp.com", address=[f"192.0.2.{n + 1}"])
    assert run(z) == []


def test_two_edge_providers_mean_no_claim():
    z = Zone()
    for n in range(3):
        z.cname(f"app{n}.example.com", f"demo{n}.herokuapp.com", address=[f"192.0.2.{n + 1}"])
    z.cname("shop.example.com", "demo.azurewebsites.net", address=["192.0.2.99"])
    assert run(z) == []
