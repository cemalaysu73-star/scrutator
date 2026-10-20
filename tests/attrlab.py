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

from dataclasses import dataclass

import respx

from scrutator.benchlab.attrlab import (  # noqa: F401 - the lab lives in the package, where `scrutator bench` runs it too
    AWS_NS,
    CLOUDFLARE_NS,
    CORP_NS,
    EXPECTED,
    LAB,
    MODULE_NAMES,
    NETWORKS,
    ORG,
    OWN_MX,
    OWN_NS,
    STRANGERS,
    TRUTH,
    TXT,
    UNDISCOVERABLE,
    cert,
    certificates,
    lab_packs,
    resolver,
    source_router,
)
from scrutator.benchlab.fakes import StatusResolver
from scrutator.model import Entity, EntityType
from scrutator.modules.base import ModuleContext
from scrutator.modules.registry import load_builtin_modules
from scrutator.report import build_report
from scrutator.scan import run_scan
from scrutator.scope import ScopePolicy
from scrutator.store import Store

SEED = Entity(type=EntityType.DOMAIN, value="example.com")
MODULES = [m for m in load_builtin_modules() if m.name in MODULE_NAMES]


def sources(router, log):
    router.route().mock(side_effect=source_router(log))


@dataclass
class Lab:
    store: Store
    scan_id: int
    dns: StatusResolver
    http_log: list
    packs: object
    report: dict


async def run_lab(http, tmp_path, *, scope=("example.com",), packs=None, store=None, dns=None, **options):
    store = store or Store(":memory:")
    dns = dns or resolver()
    packs = packs or lab_packs(tmp_path / "lab-packs")
    log: list = []
    ctx = ModuleContext(http=http, resolver=dns)
    options.setdefault("attribution", True)
    options.setdefault("max_candidates", 80)
    with respx.mock(assert_all_called=False) as router:
        sources(router, log)
        scan_id, _ = await run_scan(SEED, ScopePolicy(domains=list(scope)), store, ctx, modules=MODULES, packs=packs, **options)
    return Lab(store, scan_id, dns, log, packs, build_report(store, scan_id))


def bands(report):
    """name -> band for every listed candidate."""
    return {c["value"]: c["band"] for c in report["attribution"]["candidates"]}
