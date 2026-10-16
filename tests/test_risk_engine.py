import json
import random
from pathlib import Path

from riskfix import Zone

from scrutator.packs import load_packs
from scrutator.risk.engine import analyze, findings_from_risks, risk_from_dict

PACKS = load_packs()
LIVE = json.loads((Path(__file__).parent / "data" / "example_com_live.json").read_text(encoding="utf-8"))


def planted():
    z = Zone()
    z.ns("example.com", ["hera.ns.cloudflare.com", "elliott.ns.cloudflare.com"])
    z.dns("CAA", "example.com", "NODATA")
    z.txt("example.com", "v=spf1 include:_spf.google.com +all")
    z.cname("shop.example.com", "shop-demo.azurewebsites.net")
    z.host("dev.example.com", ["192.0.2.50"])
    z.found("old.example.com", "crtsh")
    z.dns("A", "old.example.com", "NXDOMAIN")
    return z


def rule_ids(result):
    return [r["rule_id"] for r in result["risks"]]


def test_the_planted_issues_are_found_most_severe_first():
    result = analyze(planted().report(PACKS), PACKS)
    assert rule_ids(result) == [
        "dangling-cname-claimable",
        "spf-allows-all",
        "caa-missing",
        "forgotten-name",
        "concentration-dns",
        "ghost-hostname",
    ]
    assert [r["severity"] for r in result["risks"]] == ["high", "high", "low", "low", "info", "info"]


def test_every_risk_cites_evidence_that_exists_and_only_about_names_in_the_report():
    report = planted().report(PACKS)
    entity_ids = {e["id"] for e in report["entities"]}
    for risk in analyze(report, PACKS)["risks"]:
        assert risk["evidence_ids"] and all(i in report["evidence"] for i in risk["evidence_ids"])
        assert risk["remediation"] and risk["explanation"]
        assert set(risk["entity_ids"]) <= entity_ids


def test_the_result_does_not_depend_on_the_order_of_the_report():
    report = planted().report(PACKS)
    expected = analyze(report, PACKS)
    shuffled = dict(report)
    shuffled["edges"] = random.Random(1).sample(report["edges"], len(report["edges"]))
    shuffled["entities"] = list(reversed(report["entities"]))
    shuffled["evidence"] = dict(reversed(list(report["evidence"].items())))
    assert analyze(shuffled, PACKS) == expected


def test_packs_embedded_in_the_report_give_the_same_answer_as_packs_passed_in():
    report = planted().report(PACKS)
    assert analyze(report) == analyze(report, PACKS)


def test_a_well_run_zone_has_no_findings():
    z = Zone()
    z.ns("example.com", ["hera.ns.cloudflare.com", "ns-2048.awsdns-64.com"])  # two DNS providers
    z.dns("CAA", "example.com", ['0 issue "letsencrypt.org"'])
    z.mx("example.com", ["example-com.mail.protection.outlook.com"])
    z.txt("example.com", "v=spf1 include:spf.protection.outlook.com -all")
    z.dns("TXT", "_dmarc.example.com", ['"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"'])
    z.host("www.example.com", ["192.0.2.10"])
    z.found("www.example.com", "crtsh")
    z.rdap("example.com", "2028-01-01T00:00:00Z", ["hera.ns.cloudflare.com", "ns-2048.awsdns-64.com"])
    assert analyze(z.report(PACKS), PACKS)["risks"] == []


def test_evidence_about_names_outside_the_scope_produces_nothing():
    z = Zone()
    z.cname("shop.example.org", "shop-demo.azurewebsites.net")  # a name the scope does not cover
    z.txt("example.org", "v=spf1 +all")
    z.dns("CAA", "example.org", "NODATA")
    z.ns("example.org", ["hera.ns.cloudflare.com"])
    result = analyze(z.report(PACKS), PACKS)
    assert result == {"risks": [], "dependencies": []}


def test_the_real_example_com_scan_yields_only_what_its_evidence_supports():
    result = analyze({**LIVE, "packs": PACKS.to_dict()})
    assert [(r["rule_id"], r["severity"]) for r in result["risks"]] == [("concentration-dns", "info")]
    assert "Cloudflare" in result["risks"][0]["explanation"]
    assert [(d["category"], d["provider"]) for d in result["dependencies"]] == [
        ("ca", "Sectigo"),
        ("cdn", "Cloudflare"),
        ("dns", "Cloudflare"),
    ]


def test_risks_convert_to_findings_that_keep_their_evidence():
    result = analyze(planted().report(PACKS), PACKS)
    findings = findings_from_risks(result["risks"])
    assert len(findings) == len(result["risks"])
    assert findings[0].claim.startswith("Risk (high): CNAME to a claimable service that no longer exists.")
    assert [list(f.evidence_ids) for f in findings] == [r["evidence_ids"] for r in result["risks"]]
    assert risk_from_dict(result["risks"][0]).fingerprint == result["risks"][0]["fingerprint"]
