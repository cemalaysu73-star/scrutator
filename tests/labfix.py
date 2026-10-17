"""A synthetic lab zone with every issue planted, and a clean zone as the false-positive control.

Only reserved names are used: example.com and example.net are in scope, example.org stands for
the third-party world (never queried), addresses are in 192.0.2.0/24 (TEST-NET-1) and
198.51.100.0/24 (TEST-NET-2), and AS64500 is an AS number reserved for documentation. The
sources are answered by respx with the shapes real ones use; the DNS side is a status-aware fake
resolver that knows NXDOMAIN from NODATA.
"""

import json
from datetime import datetime, timedelta, timezone

import httpx
from dnsfakes import StatusResolver
from packfix import provider, takeover, write_pack

SCOPE_DOMAINS = ["example.com", "example.net"]
TXT = lambda *texts: [f'"{t}"' for t in texts]  # noqa: E731

# every rule in the catalog is planted at least once; the value is the entity it must be about
PLANTED = {
    ("dangling-cname-claimable", "domain:shop.example.com"),
    ("dangling-cname-known-service", "domain:docs.example.com"),
    ("dangling-cname", "domain:legacy.example.com"),
    ("spf-allows-all", "domain:example.com"),
    ("spf-neutral-all", "domain:neutral.example.com"),
    ("spf-softfail-all", "domain:soft.example.com"),
    ("spf-no-all", "domain:noall.example.com"),
    ("spf-multiple-records", "domain:multi.example.com"),
    ("spf-too-many-lookups", "domain:bulk.example.com"),
    ("dmarc-missing", "domain:example.com"),
    ("dmarc-missing", "domain:oldmail.example.com"),
    ("dmarc-monitoring-only", "domain:sales.example.com"),
    ("caa-missing", "domain:example.com"),
    ("caa-missing", "domain:example.net"),
    ("domain-expiring", "domain:example.com"),
    ("domain-expired", "domain:example.net"),
    ("forgotten-name", "domain:dev.example.com"),
    ("concentration-dns", "domain:example.com"),
    ("exposed-risky-service", "ip:192.0.2.50"),
    ("ghost-hostname", "domain:ghost.example.com"),
    ("numbering-gap", "domain:app1.example.com"),
    ("source-disagreement", "domain:example.com"),
}
PLANTED_RULES = {rule for rule, _ in PLANTED} | {"concentration-edge"}


def lab_packs_dir(base):
    """Knowledge the lab needs, as data only: two providers and two takeover fingerprints."""
    write_pack(
        base,
        "lab-providers.yaml",
        "providers",
        [
            provider("lab-example-dns", provider="Example DNS", ns=["dns.example.net"]),
            provider("lab-example-edge", provider="Example Edge", category="cdn", ns=[], asn=[64500]),
        ],
    )
    write_pack(
        base,
        "lab-takeover.yaml",
        "takeover",
        [
            takeover("lab-pages", provider="Example Pages", cname=["pages.example.org"], dangling="nxdomain"),
            takeover("lab-sites", provider="Example Sites", cname=["sites.example.org"], dangling="http-fingerprint"),
        ],
    )
    return base


def lab_zone():
    zone = {
        ("example.com", "A"): ["192.0.2.1"],
        ("example.com", "NS"): ["ns1.dns.example.net.", "ns2.dns.example.net."],
        ("example.com", "MX"): ["10 mail.example.com."],
        ("example.com", "TXT"): TXT("v=spf1 include:spf.example.org +all", "site-verification=lab"),
        ("_dmarc.example.com", "TXT"): "NXDOMAIN",
        ("mail.example.com", "A"): ["192.0.2.25"],
        ("www.example.com", "A"): ["192.0.2.10"],
        ("dev.example.com", "A"): ["192.0.2.50"],
        ("app1.example.com", "A"): ["192.0.2.61"],
        ("app2.example.com", "A"): ["192.0.2.62"],
        ("app4.example.com", "A"): ["192.0.2.64"],
        ("shop.example.com", "CNAME"): ["demo.pages.example.org."],
        ("shop.example.com", "A"): "NXDOMAIN",
        ("docs.example.com", "CNAME"): ["team.sites.example.org."],
        ("docs.example.com", "A"): "NXDOMAIN",
        ("legacy.example.com", "CNAME"): ["gone.example.org."],
        ("legacy.example.com", "A"): "NXDOMAIN",
        ("neutral.example.com", "A"): ["192.0.2.71"],
        ("neutral.example.com", "TXT"): TXT("v=spf1 mx ?all"),
        ("soft.example.com", "A"): ["192.0.2.72"],
        ("soft.example.com", "TXT"): TXT("v=spf1 mx ~all"),
        ("noall.example.com", "A"): ["192.0.2.73"],
        ("noall.example.com", "TXT"): TXT("v=spf1 mx"),
        ("multi.example.com", "A"): ["192.0.2.74"],
        ("multi.example.com", "TXT"): TXT("v=spf1 mx -all", "v=spf1 a -all"),
        ("bulk.example.com", "A"): ["192.0.2.75"],
        ("bulk.example.com", "TXT"): TXT("v=spf1 " + " ".join(f"include:s{n}.example.org" for n in range(1, 12)) + " -all"),
        ("sales.example.com", "A"): ["192.0.2.76"],
        ("sales.example.com", "MX"): ["10 mail.example.com."],
        ("_dmarc.sales.example.com", "TXT"): TXT("v=DMARC1; p=none; rua=mailto:dmarc@example.com"),
        ("oldmail.example.com", "A"): ["192.0.2.77"],
        ("oldmail.example.com", "MX"): ["10 example.net."],
        ("_dmarc.oldmail.example.com", "TXT"): "NXDOMAIN",
        ("example.net", "A"): ["198.51.100.10"],
        ("example.net", "NS"): ["ns1.dns.example.net.", "ns2.dns.example.net."],
        ("ns1.dns.example.net", "A"): ["198.51.100.53"],
        ("ns2.dns.example.net", "A"): ["198.51.100.54"],
    }
    return StatusResolver(zone)


def clean_zone():
    """A well-run zone: two DNS providers, CAA, strict SPF and DMARC, one web host, no oddities."""
    zone = {
        ("example.com", "A"): ["192.0.2.1"],
        ("example.com", "NS"): ["hera.ns.cloudflare.com.", "ns-2048.awsdns-64.com."],
        ("example.com", "MX"): ["10 example-com.mail.protection.outlook.com."],
        ("example.com", "TXT"): TXT("v=spf1 include:spf.protection.outlook.com -all"),
        ("example.com", "CAA"): ['0 issue "letsencrypt.org"'],
        ("_dmarc.example.com", "TXT"): TXT("v=DMARC1; p=reject; rua=mailto:dmarc@example.com"),
        ("www.example.com", "A"): ["192.0.2.10"],
    }
    return StatusResolver(zone)


def stamp(moment):
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def mock_sources(router, *, expiry_com, expiry_net=None, rdap_com_servers=("NS1.DNS.EXAMPLE.NET",), names=(), archived=(), exposed=None):
    """Answer every source the built-in modules ask, the way the real ones do."""
    now = datetime.now(timezone.utc)
    rows = [
        {
            "id": 100 + n,
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "name_value": name,
            "not_before": (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S"),
            "not_after": (now + timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%S"),
        }
        for n, name in enumerate(names)
    ]

    def crt(request):
        return httpx.Response(200, json=rows if request.url.params.get("q") == "%.example.com" else [])

    def rdap(request):
        name = request.url.path.rsplit("/", 1)[-1]
        if name == "example.com":
            return httpx.Response(200, json=rdap_body(name, expiry_com, rdap_com_servers))
        if name == "example.net" and expiry_net is not None:
            return httpx.Response(200, json=rdap_body(name, expiry_net, ("NS1.DNS.EXAMPLE.NET", "NS2.DNS.EXAMPLE.NET")))
        return httpx.Response(404)

    def wayback(request):
        wanted = request.url.params.get("url") == "*.example.com"
        return httpx.Response(200, json=[["original"], *[[f"http://{host}/"] for host in archived]] if wanted else [["original"]])

    def ripe(request):
        return httpx.Response(200, json={"data": {"asns": [{"asn": 64500, "holder": "EXAMPLE-EDGE"}]}})

    def internetdb(request):
        ip = request.url.path.lstrip("/")
        if exposed and ip == exposed[0]:
            return httpx.Response(200, json={"ip": ip, "ports": exposed[1], "cpes": [], "vulns": [], "hostnames": [], "tags": []})
        return httpx.Response(404, json={"detail": "No information available"})

    # the other sources have nothing to add in the lab
    router.get("https://api.certspotter.com/v1/issuances").mock(return_value=httpx.Response(200, json=[]))
    router.get("https://api.hackertarget.com/hostsearch/").mock(return_value=httpx.Response(200, text="No records found"))
    router.get("https://api.subdomain.center/").mock(return_value=httpx.Response(200, json=[]))
    router.get("https://urlscan.io/api/v1/search/").mock(return_value=httpx.Response(200, json={"results": []}))
    router.get(url__regex=r"https://api\.mnemonic\.no/pdns/v3/.*").mock(return_value=httpx.Response(200, json={"responseCode": 200, "count": 0, "data": []}))
    router.get(url__regex=r"https://stat\.ripe\.net/data/(abuse-contact-finder|whois)/data\.json.*").mock(
        return_value=httpx.Response(404)
    )
    router.get(url__regex=r"https://internetdb\.shodan\.io/.*").mock(side_effect=internetdb)
    router.get("https://crt.sh/").mock(side_effect=crt)
    router.get(url__regex=r"https://rdap\.org/domain/.*").mock(side_effect=rdap)
    router.get(url__regex=r"https://rdap\.org/ip/.*").mock(return_value=httpx.Response(404))
    router.get("https://stat.ripe.net/data/prefix-overview/data.json").mock(side_effect=ripe)
    router.get("https://web.archive.org/cdx/search/cdx").mock(side_effect=wayback)
    router.get("https://index.commoncrawl.org/collinfo.json").mock(
        return_value=httpx.Response(200, json=[{"id": "CC-MAIN-LAB", "cdx-api": "https://index.commoncrawl.org/CC-MAIN-LAB-index"}])
    )
    router.get("https://index.commoncrawl.org/CC-MAIN-LAB-index").mock(return_value=httpx.Response(404))
    return now


def rdap_body(name, expiry, servers):
    return {
        "ldhName": name.upper(),
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": stamp(expiry)},
            {"eventAction": "last update of RDAP database", "eventDate": stamp(datetime.now(timezone.utc))},
        ],
        "nameservers": [{"ldhName": s} for s in servers],
    }


def lab_sources(router):
    """The lab: example.com expires in 20 days, example.net expired 5 days ago, the registry
    lists a name server the zone does not, and certificates and the archive name hosts."""
    now = datetime.now(timezone.utc)
    return mock_sources(
        router,
        expiry_com=now + timedelta(days=20),
        expiry_net=now - timedelta(days=5),
        rdap_com_servers=("NS1.DNS.EXAMPLE.NET", "NS9.OLD.EXAMPLE.NET"),
        names=[f"{label}.example.com" for label in (
            "ghost", "app1", "app2", "app4", "dev", "www", "shop", "docs", "legacy",
            "neutral", "soft", "noall", "multi", "bulk", "sales", "oldmail",
        )],
        archived=["ghost.example.com"],
        exposed=("192.0.2.50", [80, 443, 6379]),
    )


def clean_sources(router):
    now = datetime.now(timezone.utc)
    return mock_sources(
        router,
        expiry_com=now + timedelta(days=400),
        rdap_com_servers=("HERA.NS.CLOUDFLARE.COM", "NS-2048.AWSDNS-64.COM"),
        names=["www.example.com"],
    )
