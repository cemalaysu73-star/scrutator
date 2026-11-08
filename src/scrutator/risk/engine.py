"""The risk engine: a pure function of a report's own content and the pack data.

`analyze` reads only `entities`, `edges`, `evidence` and `scope` from the report, plus the
packs (passed in, or the ones embedded in the report). It reads no clock, no network, no
database. That is what lets `scrutator verify` recompute the risks from a proof bundle alone
and compare them with what the bundle claims.
"""

from scrutator.model import Finding
from scrutator.packs import PackSet
from scrutator.risk.active import active_risks
from scrutator.risk.analyst import ANALYST_RULES
from scrutator.risk.brand import brand_risks
from scrutator.risk.concentration import concentration_risks
from scrutator.risk.dependency import build_dependency_map
from scrutator.risk.hygiene import HYGIENE_RULES
from scrutator.risk.org import org_risks
from scrutator.risk.services import exposed_services
from scrutator.risk.model import Risk
from scrutator.risk.view import View

RULESET_VERSION = 5  # 2: exposed-risky-service; certspotter counts as a certificate source. 3: brand presence rules. 4: active checks (tls, http, banners, confirmed and stale exposure). 5: organisation sources (breach-history, exposed-credential, lookalike-package, brand-namespace)
_ORG_SOURCES = {"wikidata", "gleif", "hibp", "github", "github_leaks", "packages", "handles"}


def comparable(ruleset, report: dict) -> bool:
    """Can this tool re-derive risks a report says were made by `ruleset`?"""
    if ruleset == RULESET_VERSION:
        return True
    sources = {r.get("source") for r in (report.get("evidence") or {}).values() if isinstance(r, dict)}
    if ruleset == 4:
        return not sources & _ORG_SOURCES  # rule set 5 only adds what organisation evidence feeds
    if ruleset == 3:
        return not sources & ({"tcp", "tls", "http", "active"} | _ORG_SOURCES)
    if ruleset == 2:
        return "brand" not in sources and not sources & ({"tcp", "tls", "http", "active"} | _ORG_SOURCES)
    return False


def analyze(report: dict, packs: PackSet | None = None) -> dict:
    """The risks and the dependency map for a report, as plain dictionaries."""
    packs = packs if packs is not None else PackSet.from_dict(report["packs"])
    view = View(report, packs)
    deps = build_dependency_map(view)
    risks: list[Risk] = []
    for rule in HYGIENE_RULES:
        risks.extend(rule(view))
    risks.extend(concentration_risks(view, deps))
    risks.extend(exposed_services(report))
    risks.extend(brand_risks(report, packs))
    risks.extend(org_risks(report))
    risks.extend(active_risks(report))
    for rule in ANALYST_RULES:
        risks.extend(rule(view))
    risks.sort(key=lambda r: (*r.sort_key, r.fingerprint))
    return {"risks": [r.to_dict() for r in risks], "dependencies": deps.to_list()}


def risk_from_dict(data: dict) -> Risk:
    return Risk(**{key: value for key, value in data.items() if key != "fingerprint"})


def findings_from_risks(risks: list[dict]) -> list[Finding]:
    """Risks in the form the AI writer is given, most severe first, so a statement about a
    risk is verified against the same evidence as every other finding."""
    return [risk_from_dict(r).as_finding() for r in risks]
