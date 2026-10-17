"""The risk engine: a pure function of a report's own content and the pack data.

`analyze` reads only `entities`, `edges`, `evidence` and `scope` from the report, plus the
packs (passed in, or the ones embedded in the report). It reads no clock, no network, no
database. That is what lets `scrutator verify` recompute the risks from a proof bundle alone
and compare them with what the bundle claims.
"""

from scrutator.model import Finding
from scrutator.packs import PackSet
from scrutator.risk.analyst import ANALYST_RULES
from scrutator.risk.concentration import concentration_risks
from scrutator.risk.dependency import build_dependency_map
from scrutator.risk.hygiene import HYGIENE_RULES
from scrutator.risk.services import exposed_services
from scrutator.risk.model import Risk
from scrutator.risk.view import View

RULESET_VERSION = 2  # 2: exposed-risky-service; certspotter counts as a certificate source


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
