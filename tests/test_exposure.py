"""v0.6 task 4: what is known about the IP addresses of a scan: Shodan InternetDB (ports, products, CVEs,
hostnames) and RIPEstat (abuse contact, network name), kept as small replayable slices, shown in the
report and, for well-known risky ports, as a risk."""

import json

import httpx
import pytest
import respx
from riskfix import Zone

from scrutator.bundle.replay import ALLOWED_HTTP_HOSTS, supports
from scrutator.exposure import exposure
from scrutator.model import Entity, EntityType
from scrutator.modules.base import Fact, ModuleError, Observation, SourceUnavailable
from scrutator.modules.internetdb import InternetDb
from scrutator.modules.ripestat import RipeStat
from scrutator.packs import load_packs
from scrutator.risk.engine import analyze

IP = Entity(type=EntityType.IP, value="198.51.100.7")
DB = {
    "ip": "198.51.100.7",
    "ports": [22, 80, 443, 6379],
    "cpes": ["cpe:/a:openbsd:openssh:8.9", "cpe:/a:nginx:nginx"],
    "vulns": ["CVE-2023-38408"],
    "hostnames": ["www.example.com", "mail.example.org"],
    "tags": ["cloud"],
}
URL = "https://internetdb.shodan.io/198.51.100.7"


def facts(items):
    return [i for i in items if isinstance(i, Fact)]


# ------------------------------------------------------------------------------------------ InternetDB


async def test_internetdb_records_ports_products_cves_and_hostnames_as_separate_slices(make_ctx):
    with respx.mock() as router:
        router.get(URL).mock(return_value=httpx.Response(200, json=DB))
        out = await InternetDb().run(IP, make_ctx())
    by_kind = {}
    for item in facts(out):
        (row,) = json.loads(item.evidence.payload)
        by_kind[next(k for k in row if k != "ip")] = (item.evidence, row)
    assert set(by_kind) == {"ports", "cpes", "vulns"}
    assert by_kind["ports"][1] == {"ip": "198.51.100.7", "ports": [22, 80, 443, 6379]}
    assert by_kind["ports"][0].source == "internetdb" and by_kind["ports"][0].request == f"GET {URL}"
    hosts = [o for o in out if isinstance(o, Observation)]
    assert {(o.entity.value, o.rel) for o in hosts} == {("www.example.com", "known_as"), ("mail.example.org", "known_as")}
    assert json.loads(hosts[0].evidence.payload) == [{"hostnames": [hosts[0].entity.value], "ip": "198.51.100.7"}]
    assert "tags" not in json.dumps([i.evidence.payload for i in out if isinstance(i, Fact)])


async def test_internetdb_slices_replay_against_the_live_object(make_ctx):
    with respx.mock() as router:
        router.get(URL).mock(return_value=httpx.Response(200, json=DB))
        out = await InternetDb().run(IP, make_ctx())
    ports = next(i for i in facts(out) if "ports" in i.evidence.payload).evidence.payload
    assert supports(ports, json.dumps({**DB, "ports": [22, 80, 443, 6379, 8080]}))  # a new port does not unsettle the old ones
    assert not supports(ports, json.dumps({**DB, "ports": [22, 80, 443]}))  # a closed port is reported as changed


async def test_internetdb_has_no_data_for_most_addresses(make_ctx):
    with respx.mock() as router:
        router.get(URL).mock(return_value=httpx.Response(404, json={"detail": "No information available"}))
        assert await InternetDb().run(IP, make_ctx()) == []


async def test_internetdb_errors(make_ctx):
    with respx.mock() as router:
        router.get(URL).mock(return_value=httpx.Response(503))
        with pytest.raises(SourceUnavailable):
            await InternetDb().run(IP, make_ctx())
    with respx.mock() as router:
        router.get(URL).mock(return_value=httpx.Response(200, text="<html>"))
        with pytest.raises(ModuleError):
            await InternetDb().run(IP, make_ctx())


async def test_internetdb_caps_a_shared_host_list(make_ctx):
    many = {**DB, "hostnames": [f"h{i}.example.com" for i in range(300)]}
    with respx.mock() as router:
        router.get(URL).mock(return_value=httpx.Response(200, json=many))
        out = await InternetDb().run(IP, make_ctx())
    assert len([o for o in out if isinstance(o, Observation)]) == 50


def test_internetdb_asks_only_about_addresses_and_documents_its_terms():
    module = InternetDb()
    assert module.accepts == frozenset({EntityType.IP}) and module.mode.value == "passive"
    assert "non-commercial" in module.licence_note.lower()


# ------------------------------------------------------------------------------------------ RIPEstat


ABUSE = "https://stat.ripe.net/data/abuse-contact-finder/data.json"
WHOIS = "https://stat.ripe.net/data/whois/data.json"
ABUSE_BODY = {"status": "ok", "data": {"abuse_contacts": ["abuse@example.net"], "authoritative_rir": "ripe", "query_time": "2026-10-17T00:00:00"}, "time": "t"}
WHOIS_BODY = {
    "status": "ok",
    "data": {
        "records": [[
            {"key": "inetnum", "value": "198.51.100.0 - 198.51.100.255", "details_link": None},
            {"key": "netname", "value": "EXAMPLE-NET", "details_link": None},
            {"key": "descr", "value": "Example hosting", "details_link": None},
            {"key": "country", "value": "NL", "details_link": None},
            {"key": "remarks", "value": "do not copy this", "details_link": None},
        ]],
        "query_time": "2026-10-17T00:00:00",
    },
}


async def test_ripestat_keeps_the_abuse_contact_and_network_name_with_sourceapp(make_ctx):
    with respx.mock() as router:
        a = router.get(ABUSE).mock(return_value=httpx.Response(200, json=ABUSE_BODY))
        w = router.get(WHOIS).mock(return_value=httpx.Response(200, json=WHOIS_BODY))
        out = await RipeStat().run(IP, make_ctx())
    assert a.calls[0].request.url.params["sourceapp"] == "scrutator" and w.calls[0].request.url.params["sourceapp"] == "scrutator"
    assert all(isinstance(i, Fact) for i in out) and len(out) == 2
    abuse = next(i.evidence for i in out if "abuse" in i.evidence.request)
    assert json.loads(abuse.payload) == [{"abuse_contacts": ["abuse@example.net"]}]
    whois = next(i.evidence for i in out if "whois" in i.evidence.request)
    rows = json.loads(whois.payload)
    assert {r["key"] for r in rows} == {"netname", "descr", "country"} and "remarks" not in whois.payload
    assert supports(abuse.payload, json.dumps(ABUSE_BODY)) and supports(whois.payload, json.dumps(WHOIS_BODY))
    assert abuse.source == "ripestat"


async def test_ripestat_one_call_failing_keeps_the_other(make_ctx):
    with respx.mock() as router:
        router.get(ABUSE).mock(return_value=httpx.Response(200, json=ABUSE_BODY))
        router.get(WHOIS).mock(return_value=httpx.Response(500))
        out = await RipeStat().run(IP, make_ctx())
    assert len(out) == 1 and "abuse" in out[0].evidence.request


async def test_ripestat_both_failing_is_a_source_failure(make_ctx):
    with respx.mock() as router:
        router.get(ABUSE).mock(return_value=httpx.Response(503))
        router.get(WHOIS).mock(return_value=httpx.Response(503))
        with pytest.raises(SourceUnavailable):
            await RipeStat().run(IP, make_ctx())


def test_ripestat_calls_share_the_limit_of_the_asn_module_and_state_the_terms():
    from scrutator.modules.asn import Asn

    assert RipeStat.rate_group == Asn.rate_group == "ripestat"
    assert "non-commercial" in RipeStat.licence_note.lower() and "ripe" in RipeStat.licence_note.lower()


async def test_the_asn_request_names_the_application(make_ctx):
    from scrutator.modules.asn import Asn

    with respx.mock() as router:
        route = router.get("https://stat.ripe.net/data/prefix-overview/data.json").mock(
            return_value=httpx.Response(200, json={"data": {"asns": []}})
        )
        await Asn().run(IP, make_ctx())
    assert route.calls[0].request.url.params["sourceapp"] == "scrutator"


def test_the_allowlist_has_internetdb():
    assert "internetdb.shodan.io" in ALLOWED_HTTP_HOSTS


# ------------------------------------------------------------------------------------------ the report


def zone_with_exposure():
    z = Zone()
    z.host("www.example.com", ["198.51.100.7"])
    ports = z.ev("internetdb", f"GET {URL}", json.dumps([{"ip": "198.51.100.7", "ports": [22, 6379]}]))
    cves = z.ev("internetdb", f"GET {URL}", json.dumps([{"ip": "198.51.100.7", "vulns": ["CVE-2023-38408"]}]))
    cpes = z.ev("internetdb", f"GET {URL}", json.dumps([{"ip": "198.51.100.7", "cpes": ["cpe:/a:nginx:nginx"]}]))
    abuse = z.ev("ripestat", "GET https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=198.51.100.7&sourceapp=scrutator", json.dumps([{"abuse_contacts": ["abuse@example.net"]}]))
    whois = z.ev("ripestat", "GET https://stat.ripe.net/data/whois/data.json?resource=198.51.100.7&sourceapp=scrutator", json.dumps([{"key": "netname", "value": "EXAMPLE-NET"}, {"key": "country", "value": "NL"}]))
    return z, dict(ports=ports, cves=cves, cpes=cpes, abuse=abuse, whois=whois)


def test_exposure_is_derived_from_the_evidence_of_in_scope_and_linked_addresses():
    z, ev = zone_with_exposure()
    rows = exposure(z.report())
    assert rows == [
        {
            "ip": "198.51.100.7",
            "state": "linked",
            "ports": [22, 6379],
            "cpes": ["cpe:/a:nginx:nginx"],
            "vulns": ["CVE-2023-38408"],
            "hostnames": [],
            "abuse_contacts": ["abuse@example.net"],
            "netname": "EXAMPLE-NET",
            "country": "NL",
            "description": "",
            "evidence_ids": sorted(ev.values()),
        }
    ]


def test_evidence_about_an_address_the_scan_did_not_link_is_ignored():
    z, _ = zone_with_exposure()
    z.entity("ip", "203.0.113.9", "out")
    z.ev("internetdb", "GET https://internetdb.shodan.io/203.0.113.9", json.dumps([{"ip": "203.0.113.9", "ports": [23]}]))
    assert [r["ip"] for r in exposure(z.report())] == ["198.51.100.7"]
    z2 = Zone()  # evidence for an address that is not an entity at all
    z2.ev("internetdb", URL, json.dumps([{"ip": "198.51.100.7", "ports": [23]}]))
    assert exposure(z2.report()) == []


def test_a_risky_port_is_a_low_confidence_risk_that_cites_its_evidence():
    z, ev = zone_with_exposure()
    risks = [r for r in analyze(z.report(), load_packs())["risks"] if r["rule_id"] == "exposed-risky-service"]
    assert len(risks) == 1
    (risk,) = risks
    assert risk["entity_ids"] == ["ip:198.51.100.7"] and risk["evidence_ids"] == [ev["ports"]]
    assert risk["severity"] == "medium" and risk["confidence"] == "low"
    assert "6379" in risk["explanation"] and "Redis" in risk["explanation"] and "SSH" not in risk["explanation"]
    assert "InternetDB" in risk["explanation"]


def test_ordinary_web_and_ssh_ports_are_not_a_risk():
    z = Zone()
    z.host("www.example.com", ["198.51.100.7"])
    z.ev("internetdb", URL, json.dumps([{"ip": "198.51.100.7", "ports": [22, 80, 443, 8443]}]))
    assert [r for r in analyze(z.report(), load_packs())["risks"] if r["rule_id"] == "exposed-risky-service"] == []


def test_the_report_and_its_html_carry_the_exposure_table():
    from scrutator.report.html import render_html

    z, _ = zone_with_exposure()
    report = z.report()
    report["exposure"] = exposure(report)
    page = render_html({**report, "tool": {"name": "scrutator", "version": "x"}, "scan": {"id": 1, "seed": "example.com", "started_at": "t"}, "summary": {"entities": 0, "by_type": {}, "by_scope": {}, "edges": 0, "findings": 0, "risks": 0, "candidates": 0, "leads": 0}})
    assert "exposure" in page.lower()


def test_a_bundle_checks_the_address_table_against_its_evidence(tmp_path):
    from riskbundlefix import forge_report, make_risky_bundle

    from scrutator.bundle.verify import verify_bundle

    fx = make_risky_bundle(tmp_path)
    genuine = verify_bundle(fx.path)
    assert genuine.ok and any(c.name == "exposure derivable" and c.ok for c in genuine.checks)

    def invent(report):
        report["exposure"] = [{"ip": "192.0.2.1", "state": "linked", "ports": [23], "cpes": [], "vulns": [], "hostnames": [], "abuse_contacts": [], "netname": "", "country": "", "description": "", "evidence_ids": []}]

    forged = verify_bundle(forge_report(fx.path, tmp_path / "f.scrutator", fx.private, invent))
    assert next(c for c in forged.checks if c.name == "signature valid").ok
    assert [c.name for c in forged.checks if not c.ok] == ["exposure derivable"]
