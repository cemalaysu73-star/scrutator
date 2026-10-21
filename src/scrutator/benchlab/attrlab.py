"""The planted attribution lab: an organisation (example.com) with 16 other names that belong to it
and a set of decoys that look like they might, answered by a status-aware fake resolver and mocked
sources. Only reserved names are used: example.com is the scope; every other name ends in `.test`;
addresses are in 192.0.2.0/24 (the organisation's own network, AS64510), 198.51.100.0/24 (a shared
hosting provider, AS64500) and 203.0.113.0/24; AS numbers are from the documentation range.

Each lab name says whether it is the organisation's (`true`), how a scan can find it at all
(`cert`: a certificate that lists it with example.com), and what its own DNS and registration
records say. A true name with no way to be found (`hidden.test`) counts against recall.

The decoys are the cases the scoring was designed around, and the ones it cannot solve:
  hosting-client, cf-blog, stranger00..24   a shared service's certificate, a hosting AS, Cloudflare's name servers
  _spf.vendor-mail, ns1/ns2.corp-dns        names the scope points at: a vendor and a DNS operator
  partner, tinyhost                         a co-branded certificate or an old one, plus the same small DNS operator
  client                                    DNS run by the organisation for a customer: indistinguishable from its own
                                            from DNS alone, so it is a planted false positive that no signal can remove
"""

from pathlib import Path

import httpx

from scrutator.benchlab.fakes import Router, StatusResolver, provider, write_pack
from scrutator.packs import load_packs

ORG = "Example Corporation"
OWN_NS = ["ns1.example.com.", "ns2.example.com."]
CORP_NS = ["ns1.corp-dns.test.", "ns2.corp-dns.test."]
CLOUDFLARE_NS = ["hera.ns.cloudflare.com.", "elliott.ns.cloudflare.com."]
AWS_NS = ["ns-1.awsdns-01.com.", "ns-2.awsdns-02.org."]
OWN_MX = ["10 mail.example.com."]
STRANGERS = [f"stranger{n:02}.test" for n in range(25)]
TXT = lambda *texts: [f'"{t}"' for t in texts]  # noqa: E731
MODULE_NAMES = {"dns", "rdap", "crtsh", "asn"}

# name -> what the lab says about it
LAB = {
    # the organisation's own, found through a certificate that also lists example.com
    "pay.test": dict(true=True, cert="pair", ns=OWN_NS),
    "app.test": dict(true=True, cert="pair", ns=OWN_NS, mx=OWN_MX),
    "corp.test": dict(true=True, cert="pair", ns=OWN_NS, reg=ORG),
    "eu.test": dict(true=True, cert="pair", ns=OWN_NS),
    "labs.test": dict(true=True, cert="pair", ns=OWN_NS, reg=ORG.upper()),
    "mobile.test": dict(true=True, cert="stale", ns=OWN_NS),
    "docs.test": dict(true=True, cert="pair", mx=OWN_MX),
    "status.test": dict(true=True, cert="stale", mx=OWN_MX),
    "mail.test": dict(true=True, cert="pair", spf="v=spf1 include:_spf.example.com -all"),
    "news.test": dict(true=True, cert="stale", reg=ORG),
    "media.test": dict(true=True, cert="pair", reg=ORG),
    "b2b.test": dict(true=True, cert="pair", ns=CORP_NS, ip="192.0.2.98"),
    "archive.test": dict(true=True, cert="stale"),
    # the organisation's own, found because the scope points at it
    "games.test": dict(true=True, reg=ORG),
    "relay.test": dict(true=True, ip="192.0.2.99"),
    # the organisation's own, and nothing links it to anything the scan can reach
    "hidden.test": dict(true=True, ns=OWN_NS, reg=ORG),
    # decoys
    "client.test": dict(true=False, cert="pair", ns=OWN_NS),
    "partner.test": dict(true=False, cert="pair", ns=CORP_NS, reg="REDACTED FOR PRIVACY"),
    "tinyhost.test": dict(true=False, cert="stale", ns=CORP_NS),
    "hosting-client.test": dict(true=False, cert="big", ip="198.51.100.77"),
    "cf-blog.test": dict(true=False, cert="big", ns=CLOUDFLARE_NS),
    "_spf.vendor-mail.test": dict(true=False, ns=AWS_NS),
}
TRUTH = {f"domain:{name}" for name, spec in LAB.items() if spec["true"]}
UNDISCOVERABLE = {"hidden.test"}

# the band the scoring is designed to give each name (tests/test_attribution_lab.py checks all of them)
EXPECTED = {
    "confirmed": {"pay.test", "app.test", "corp.test", "eu.test", "labs.test", "mobile.test", "client.test"},
    "probable": {"docs.test", "status.test", "mail.test", "news.test", "media.test"},
    "possible": {"games.test", "b2b.test", "relay.test", "partner.test", "tinyhost.test"},
    "unlikely": {"archive.test", "hosting-client.test", "cf-blog.test", "_spf.vendor-mail.test", "ns1.corp-dns.test", "ns2.corp-dns.test", *STRANGERS},
}


def lab_packs(base: Path):
    """Knowledge the lab needs, as data only: the shared hosting provider's AS number."""
    return load_packs([write_pack(base, "lab-providers.yaml", "providers", [provider("lab-hosting", provider="Example Hosting", category="hosting", ns=[], asn=[64500])])])


def resolver() -> StatusResolver:
    zone = {
        ("example.com", "A"): ["192.0.2.1"],
        ("example.com", "NS"): OWN_NS,
        ("example.com", "MX"): OWN_MX,
        ("example.com", "TXT"): TXT("v=spf1 include:_spf.vendor-mail.test include:games.test -all"),
        ("_dmarc.example.com", "TXT"): TXT("v=DMARC1; p=reject"),
        ("ns1.example.com", "A"): ["192.0.2.53"],
        ("ns2.example.com", "A"): ["192.0.2.54"],
        ("mail.example.com", "A"): ["192.0.2.25"],
        ("www.example.com", "A"): ["192.0.2.10"],
        ("static.example.com", "A"): ["104.16.0.1"],
        ("static.example.com", "NS"): CLOUDFLARE_NS,
        ("corp.example.com", "A"): ["192.0.2.20"],
        ("corp.example.com", "NS"): CORP_NS,
        ("corp.example.com", "MX"): ["10 relay.test."],
        ("site.example.com", "A"): ["198.51.100.5"],
    }
    for name, spec in LAB.items():
        if spec.get("ns"):
            zone[(name, "NS")] = spec["ns"]
        if spec.get("mx"):
            zone[(name, "MX")] = spec["mx"]
        if spec.get("spf"):
            zone[(name, "TXT")] = TXT(spec["spf"])
        if spec.get("ip"):
            zone[(name, "A")] = [spec["ip"]]
    return StatusResolver(zone)


def cert(cert_id, names, *, stale=False):
    return {
        "id": cert_id,
        "issuer_name": "C=ZZ, O=Example Internal, CN=Example Issuing CA",
        "name_value": "\n".join(names),
        "not_before": "2016-07-14T00:00:00" if stale else "2026-09-01T00:00:00",
        "not_after": "2017-07-14T23:59:59" if stale else "2026-12-01T00:00:00",
    }


def certificates():
    rows = [cert(1, ["example.com", "www.example.com", "mail.example.com", "ns1.example.com", "ns2.example.com", "static.example.com", "corp.example.com", "site.example.com"])]
    for number, (name, spec) in enumerate(LAB.items(), start=10):
        if spec.get("cert") in ("pair", "stale"):
            rows.append(cert(number, ["example.com", name], stale=spec["cert"] == "stale"))
    rows.append(cert(99, ["example.com", "hosting-client.test", "cf-blog.test", *STRANGERS]))  # 28 names: a shared service's certificate
    return rows


NETWORKS = (("192.0.2.", 64510, "EXAMPLE-CORP-NET"), ("198.51.100.", 64500, "EXAMPLE-HOSTING-NET"), ("104.16.", 13335, "CLOUDFLARENET"), ("203.0.113.", 64511, "OTHER-NET"))


def source_router(log: list) -> Router:
    def crt(request):
        query = request.url.params.get("q")
        log.append(("crt", query))
        return httpx.Response(200, json=certificates() if query == "%.example.com" else [])

    def rdap_domain(request):
        name = request.url.path.rsplit("/", 1)[-1]
        log.append(("rdap", name))
        org = ORG if name == "example.com" else LAB.get(name, {}).get("reg")
        if org is None:
            return httpx.Response(404)
        return httpx.Response(200, json={"ldhName": name.upper(), "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", org]]]}]})

    def rdap_ip(request):
        ip = request.url.path.rsplit("/", 1)[-1]
        log.append(("rdap-ip", ip))
        for prefix, _, owner in NETWORKS:
            if ip.startswith(prefix):
                return httpx.Response(200, json={"name": owner})
        return httpx.Response(404)

    def ripe(request):
        ip = request.url.params.get("resource")
        log.append(("asn", ip))
        for prefix, asn, _ in NETWORKS:
            if ip.startswith(prefix):
                return httpx.Response(200, json={"data": {"asns": [{"asn": asn}]}})
        return httpx.Response(200, json={"data": {"asns": []}})

    router = Router()
    router.add("crt.sh", "/", crt)
    router.add("rdap.org", r"/domain/.*", rdap_domain, regex=True)
    router.add_rdap_ip(rdap_ip)
    router.add("stat.ripe.net", "/data/prefix-overview/data.json", ripe)
    return router
