"""A small scan with a candidate in it, shared by the attribution tests.

example.com is the scope. A certificate lists example.com and partner.test (which is delegated to
example.com's own name server); another lists example.com, vendor.test and 38 strangers (a shared
service's certificate); the SPF record includes a vendor. Real modules, a status-aware fake resolver
and mocked sources: no network."""

import httpx
import respx
from dataclasses import dataclass

from dnsfakes import StatusResolver

from scrutator.model import Entity, EntityType
from scrutator.modules.base import ModuleContext
from scrutator.modules.registry import load_builtin_modules
from scrutator.packs import load_packs
from scrutator.report import build_report
from scrutator.scan import run_scan
from scrutator.scope import ScopePolicy
from scrutator.store import Store

SEED = Entity(type=EntityType.DOMAIN, value="example.com")
MODULES = [m for m in load_builtin_modules() if m.name in {"dns", "rdap", "crtsh", "asn"}]
BIG = [f"t{n}.test" for n in range(38)]
TXT = lambda *texts: [f'"{t}"' for t in texts]  # noqa: E731


def cert(cert_id, *names):
    return {
        "id": cert_id,
        "issuer_name": "C=ZZ, O=Example Internal, CN=Example Issuing CA",
        "name_value": "\n".join(names),
        "not_before": "2026-09-01T00:00:00",
        "not_after": "2026-12-01T00:00:00",
    }


def resolver():
    return StatusResolver(
        {
            ("example.com", "A"): ["192.0.2.1"],
            ("example.com", "NS"): ["ns1.example.com.", "ns2.example.com."],
            ("example.com", "TXT"): TXT("v=spf1 include:_spf.vendor2.test -all"),
            ("ns1.example.com", "A"): ["192.0.2.53"],
            ("ns2.example.com", "A"): ["192.0.2.54"],
            ("www.example.com", "A"): ["192.0.2.10"],
            ("partner.test", "A"): ["198.51.100.7"],
            ("partner.test", "NS"): ["ns1.example.com.", "ns9.partner-dns.test."],
            ("_spf.vendor2.test", "A"): ["203.0.113.9"],
            ("vendor.test", "A"): ["203.0.113.10"],
            ("decoy.test", "A"): ["203.0.113.66"],
        }
    )


def sources(router, log):
    def crt(request):
        query = request.url.params.get("q")
        log.append(("crt", query))
        if query == "%.example.com":
            return httpx.Response(
                200,
                json=[cert(1, "example.com", "www.example.com"), cert(2, "example.com", "partner.test"), cert(3, "example.com", "vendor.test", *BIG)],
            )
        return httpx.Response(200, json=[])

    def rdap(request):
        name = request.url.path.rsplit("/", 1)[-1]
        log.append(("rdap", name))
        return httpx.Response(200, json={"ldhName": name.upper()}) if name in {"example.com", "partner.test"} else httpx.Response(404)

    def ripe(request):
        log.append(("asn", request.url.params.get("resource")))
        return httpx.Response(200, json={"data": {"asns": [{"asn": 64500}]}})

    router.get("https://crt.sh/").mock(side_effect=crt)
    router.get(url__regex=r"https://rdap\.org/domain/.*").mock(side_effect=rdap)
    router.get(url__regex=r"https://rdap\.org/ip/.*").mock(return_value=httpx.Response(404))
    router.get("https://stat.ripe.net/data/prefix-overview/data.json").mock(side_effect=ripe)


@dataclass
class Run:
    store: Store
    scan_id: int
    dns: StatusResolver
    http_log: list
    report: dict


async def scan(http, **options):
    store, dns, log = Store(":memory:"), resolver(), []
    ctx = ModuleContext(http=http, resolver=dns)
    with respx.mock(assert_all_called=False) as router:
        sources(router, log)
        scan_id, _ = await run_scan(SEED, ScopePolicy(domains=["example.com"]), store, ctx, modules=MODULES, packs=load_packs(), **options)
    return Run(store, scan_id, dns, log, build_report(store, scan_id))


def states(run):
    return {s.entity.value: s.state for s in run.store.entities(run.scan_id)}
