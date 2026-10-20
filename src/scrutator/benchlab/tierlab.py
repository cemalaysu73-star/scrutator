"""The name-tier lab: one zone without a wildcard (example.com) and one with (example.net), and names that each
land in a tier for a stated reason. Certificates (crt.sh), an aggregator (Subdomain Center) and an archive
(Wayback) name them; DNS decides. `EXPECTED` is the tier the evidence must give each name."""

from datetime import datetime, timedelta, timezone

import httpx

from scrutator.benchlab.fakes import Router, StatusResolver

SCOPE_DOMAINS = ["example.com", "example.net"]
MODULE_NAMES = {"dns", "wildcard", "crtsh", "subdomaincenter", "wayback"}
WILDCARD_ADDRESS = "198.51.100.200"

# name -> (expected tier, why)
EXPECTED = {
    "example.com": ("verified", "an address"),
    "www.example.com": ("verified", "an address"),
    "mailonly.example.com": ("verified", "an MX record and no address"),
    "quiet.example.com": ("verified", "a certificate valid now, and DNS holds no address (no contradiction)"),
    "ghost.example.com": ("stale", "a current certificate, but NXDOMAIN"),
    "oldcert.example.com": ("stale", "a certificate that expired years ago, and NXDOMAIN"),
    "aggr.example.com": ("claimed", "only an aggregator names it, and NXDOMAIN"),
    "archived.example.com": ("claimed", "only the archive names it, and NXDOMAIN"),
    "example.net": ("verified", "an address"),
    "api.example.net": ("verified", "an address of its own, not the wildcard's"),
    "shop.example.net": ("verified", "only the wildcard answers, but a current certificate names it"),
    "blog.example.net": ("wildcard", "only the wildcard answers and only an aggregator names it"),
    "old.example.net": ("wildcard", "only the wildcard answers and its certificate expired years ago"),
}


def resolver() -> StatusResolver:
    zone = {
        ("example.com", "A"): ["192.0.2.1"],
        ("example.com", "NS"): ["ns1.example.com."],
        ("ns1.example.com", "A"): ["192.0.2.53"],
        ("www.example.com", "A"): ["192.0.2.10"],
        ("mailonly.example.com", "MX"): ["10 mail.example.com."],
        ("mail.example.com", "A"): ["192.0.2.25"],
        ("quiet.example.com", "CAA"): ['0 issue "example.org"'],  # exists, but has nothing the scan asks about
        ("example.net", "A"): ["198.51.100.1"],
        ("example.net", "NS"): ["ns1.example.com."],
        ("api.example.net", "A"): ["198.51.100.50"],
    }
    return StatusResolver(zone, wildcards={"example.net": [WILDCARD_ADDRESS]})


def source_router() -> Router:
    now = datetime.now(timezone.utc)
    fresh = (now + timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%S")

    def cert(cert_id, name, not_after):
        return {"id": cert_id, "issuer_name": "C=US, O=Let's Encrypt, CN=R3", "name_value": name,
                "not_before": "2019-01-01T00:00:00", "not_after": not_after}

    certs = {
        "%.example.com": [cert(1, "www.example.com", fresh), cert(2, "quiet.example.com", fresh), cert(3, "ghost.example.com", fresh),
                          cert(4, "oldcert.example.com", "2019-06-01T00:00:00"), cert(5, "mailonly.example.com", fresh)],
        "%.example.net": [cert(6, "shop.example.net", fresh), cert(7, "old.example.net", "2019-06-01T00:00:00"), cert(8, "api.example.net", fresh)],
    }
    listed = {"example.com": ["aggr.example.com"], "example.net": ["blog.example.net"]}
    archived = {"*.example.com": ["archived.example.com"]}

    router = Router()
    router.add("crt.sh", "/", lambda r: httpx.Response(200, json=certs.get(r.url.params.get("q"), [])))
    router.add("api.subdomain.center", "/", lambda r: httpx.Response(200, json=listed.get(r.url.params.get("domain"), [])))
    router.add("web.archive.org", "/cdx/search/cdx", lambda r: httpx.Response(
        200, json=[["original"], *[[f"http://{h}/"] for h in archived.get(r.url.params.get("url"), [])]]))
    return router
