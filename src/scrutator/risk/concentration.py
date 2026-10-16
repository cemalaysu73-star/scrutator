"""Concentration rules: how many names depend on one provider.

A "single provider" claim needs every relevant host to be recognised by the pack data. If even
one name server is unknown, the rule stays silent rather than guess. The mail provider is a
dependency (it appears in the dependency map), not a risk: one mail provider is the norm.
"""

from scrutator.model import Confidence
from scrutator.risk.catalog import make
from scrutator.risk.dependency import DependencyMap, build_dependency_map
from scrutator.risk.model import Risk, Severity
from scrutator.risk.view import View

_MAX_ENTITIES = 10


def _ids(names) -> list[str]:
    return [f"domain:{n}" for n in sorted(names)[:_MAX_ENTITIES]]


def _dns(view: View, deps: DependencyMap) -> list[Risk]:
    providers = deps.of("dns")
    if len(providers) != 1 or deps.unmatched_ns:
        return []
    only = providers[0]
    count = len(only.hostnames)
    zones = sorted(e.removeprefix("domain:") for e in only.entity_ids)
    return [
        make(
            "concentration-dns", _ids(zones), sorted(only.evidence_ids),
            f"The name servers of {', '.join(zones)} all belong to {only.provider}; {count} in-scope name(s) sit in "
            f"{'this zone' if len(zones) == 1 else 'these zones'}.",
            Confidence.HIGH if only.verified else Confidence.MEDIUM,
            severity=Severity.LOW if count >= 10 else Severity.INFO,
        )
    ]


def _edge(view: View, deps: DependencyMap) -> list[Risk]:
    by_provider: dict[str, list] = {}
    for item in deps.of("cdn", "hosting"):
        by_provider.setdefault(item.provider, []).append(item)
    if len(by_provider) != 1:
        return []
    ((provider, items),) = by_provider.items()
    names = set().union(*(i.hostnames for i in items))
    evidence = sorted(set().union(*(i.evidence_ids for i in items)))
    if len(names) < 3:
        return []
    return [
        make(
            "concentration-edge", _ids(names), evidence,
            f"{len(names)} in-scope names are served through {provider} ({', '.join(sorted(names)[:_MAX_ENTITIES])}).",
            Confidence.HIGH if all(i.verified for i in items) else Confidence.MEDIUM,
            severity=Severity.LOW if len(names) >= 10 else Severity.INFO,
        )
    ]


def concentration_risks(view: View, deps: DependencyMap | None = None) -> list[Risk]:
    deps = deps or build_dependency_map(view)
    return [*_dns(view, deps), *_edge(view, deps)]
