"""The dependency map: which third-party providers stand behind the in-scope names.

DNS provider from the NS records of each zone, mail provider from MX targets and SPF includes,
CDN or hosting provider from CNAME targets and from the AS number behind each address, and
the certificate authority from the issuer of certificates valid when the data was collected.
Only names the pack data recognises are listed; an unrecognised host is not guessed at.
"""

import json
import re
from dataclasses import dataclass, field

from scrutator.risk.view import View, host, parse_time, txt_values

_SPF_INCLUDE = re.compile(r"(?i)\binclude:([^\s]+)")


@dataclass
class Dependency:
    category: str
    provider: str
    verified: bool = True
    via: set[str] = field(default_factory=set)
    hostnames: set[str] = field(default_factory=set)
    targets: set[str] = field(default_factory=set)
    evidence_ids: set[str] = field(default_factory=set)
    entity_ids: set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "provider": self.provider,
            "verified": self.verified,
            "via": sorted(self.via),
            "hostnames": sorted(self.hostnames),
            "targets": sorted(self.targets),
            "evidence_ids": sorted(self.evidence_ids),
        }


@dataclass
class DependencyMap:
    items: dict[tuple[str, str], Dependency] = field(default_factory=dict)
    # NS targets of a zone that no provider entry recognises: a "single provider" claim needs none
    unmatched_ns: dict[str, list[str]] = field(default_factory=dict)
    unmatched_mx: dict[str, list[str]] = field(default_factory=dict)

    def add(self, entry, via: str, name: str, target: str, evidence_ids, hostnames=None) -> None:
        item = self.items.setdefault((entry.category, entry.provider), Dependency(entry.category, entry.provider))
        item.verified = item.verified and entry.verified
        item.via.add(via)
        item.hostnames.update(hostnames if hostnames is not None else [name])
        item.targets.add(target)
        item.evidence_ids.update(evidence_ids)
        item.entity_ids.add(f"domain:{name}")

    def of(self, *categories: str) -> list[Dependency]:
        return sorted(
            (d for d in self.items.values() if d.category in categories),
            key=lambda d: (d.category, d.provider),
        )

    def to_list(self) -> list[dict]:
        return [d.to_dict() for d in self.of("dns", "mail", "cdn", "hosting", "ca")]


def build_dependency_map(view: View) -> DependencyMap:
    packs = view.packs
    deps = DependencyMap()
    names = sorted(view.names)
    zones = view.zone_apexes()

    # DNS provider: every name depends on the zone it sits in
    for zone in zones:
        ns_evidence = view.dns("NS", zone).evidence_id
        members = [n for n in names if view.zone_of(n, zones) == zone]
        for target in view.targets("NS", zone):
            entry = packs.match_provider("ns", target)
            if entry is None:
                deps.unmatched_ns.setdefault(zone, []).append(target)
            else:
                deps.add(entry, "ns", zone, target, [ns_evidence], hostnames=members)

    for name in names:
        # mail provider: MX targets, then SPF includes
        mx = view.dns("MX", name)
        for target in view.targets("MX", name):
            entry = packs.match_provider("mx", target)
            if entry is None:
                deps.unmatched_mx.setdefault(name, []).append(target)
            else:
                deps.add(entry, "mx", name, target, [mx.evidence_id])
        txt = view.dns("TXT", name)
        if txt is not None:
            for value in txt_values(view.answers("TXT", name)):
                if "v=spf1" not in value.lower():
                    continue
                for include in _SPF_INCLUDE.findall(value):
                    entry = packs.match_provider("spf", host(include))
                    if entry is not None:
                        deps.add(entry, "spf", name, host(include), [txt.evidence_id])

        # CDN or hosting: where a CNAME points, and which AS announces the addresses
        cname = view.dns("CNAME", name)
        for target in view.targets("CNAME", name):
            entry = packs.match_provider("cname", target)
            if entry is not None:
                deps.add(entry, "cname", name, target, [cname.evidence_id])
        for edge in view.edges_from(f"domain:{name}", "resolves_to"):
            for onward in view.edges_from(edge["dst"], "announced_by"):
                asn = view.entities.get(onward["dst"])
                entry = packs.match_provider("asn", asn["value"]) if asn else None
                if entry is not None:
                    deps.add(entry, "asn", name, asn["value"], [*edge["evidence_ids"], *onward["evidence_ids"]])

        # certificate authority: issuers of certificates that were valid when the data was collected
        for edge in view.edges_into(f"domain:{name}"):
            for evidence_id in edge["evidence_ids"]:
                record = view.evidence.get(evidence_id)
                if record and record["source"] == "crtsh":
                    _add_issuers(deps, packs, name, evidence_id, record)
    return deps


def _add_issuers(deps: DependencyMap, packs, name: str, evidence_id: str, record: dict) -> None:
    try:
        certs = json.loads(record["payload"])
    except ValueError:
        return
    collected = parse_time(record["collected_at"])
    if not isinstance(certs, list) or collected is None:
        return
    for cert in certs:
        if not isinstance(cert, dict):
            continue
        start, end = parse_time(cert.get("not_before", "")), parse_time(cert.get("not_after", ""))
        if start is None or end is None or not start <= collected <= end:
            continue
        issuer = str(cert.get("issuer_name", ""))
        entry = packs.match_provider("issuer", issuer)
        if entry is not None:
            deps.add(entry, "issuer", name, issuer, [evidence_id])
