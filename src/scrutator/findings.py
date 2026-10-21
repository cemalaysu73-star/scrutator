from scrutator.model import Confidence, Finding
from scrutator.names import name_states
from scrutator.store import Store

_REL_TEXT = {
    "resolves_to": "resolves to",
    "has_subdomain": "has subdomain",
    "related_host": "is related to host",
    "cname_to": "is an alias (CNAME) of",
    "mx": "uses mail server",
    "ns": "uses name server",
    "spf_include": "authorises senders via SPF include",
    "announced_by": "is announced by",
    "registrar": "is registered via",
    "netblock_owner": "belongs to network owned by",
    "known_as": "is known to Shodan as",
    "historically_resolved_to": "was seen resolving to",
    "historic_cname": "was seen as an alias (CNAME) of",
    "historic_ns": "was seen using name server",
    "historic_mx": "was seen using mail server",
    "mentions": "has a record that mentions",
    "reverse_dns": "has a PTR record naming",
}


def confidence_for(distinct_sources: int) -> Confidence:
    if distinct_sources >= 3:
        return Confidence.HIGH
    if distinct_sources == 2:
        return Confidence.MEDIUM
    return Confidence.LOW


def claim_for(src_value: str, rel: str, dst_value: str) -> str:
    return f"{src_value} {_REL_TEXT.get(rel, rel.replace('_', ' '))} {dst_value}"


def build_findings(store: Store, scan_id: int) -> list[Finding]:
    """One finding per graph edge. Confidence counts distinct sources, not records."""
    values = {s.entity.id: s.entity.value for s in store.entities(scan_id)}
    findings: list[Finding] = []
    for edge in store.edges(scan_id):
        sources = set()
        for evidence_id in edge.evidence_ids:
            evidence = store.get_evidence(evidence_id)
            if evidence is not None:
                sources.add(evidence.source)
        findings.append(
            Finding(
                claim=claim_for(values.get(edge.src, edge.src), edge.rel, values.get(edge.dst, edge.dst)),
                entity_ids=(edge.src, edge.dst),
                evidence_ids=edge.evidence_ids,
                confidence=confidence_for(len(sources)),
            )
        )
    return findings


FINDING_TIERS = ("verified", "other", "claimed", "stale", "wildcard")
_NAMING_RELS = frozenset({"has_subdomain", "related_host", "known_as", "mentions", "reverse_dns"})


def finding_tier(rel: str, src: str, dst: str, tiers: dict[str, str]) -> str:
    """How well a relation is supported, by the name it is about: `verified`, `claimed`, `stale` or
    `wildcard` as that name's tier, or `other` when it is about no in-scope name (an address and its
    network, a registrar). A listing relation ("example.com has subdomain x") is about the listed
    name, any other relation about the name it starts from."""
    order = (dst, src) if rel in _NAMING_RELS else (src, dst)
    for value in order:
        if value in tiers:
            return tiers[value]
    return "other"


def findings_from_report(report: dict, *, tiered: bool = True, names: list[dict] | None = None) -> list[dict]:
    """Recompute the findings a report must contain from its own entities, edges and
    evidence. A report whose findings differ from this has been altered or is inconsistent.

    Each finding carries the tier of the name it is about (see `finding_tier`) and the list is ordered
    verified first, then by the relation order. `tiered=False` is the v0.6 shape (no tier, relation
    order), which is what a bundle made before tiers existed holds. `names` are the report's name
    states when the caller has them already (derived, never read from the report being checked)."""
    values = {e["id"]: e["value"] for e in report["entities"]}
    evidence = report["evidence"]
    tiers = {row["name"]: row["tier"] for row in (names if names is not None else name_states(report))} if tiered else {}
    rebuilt = []
    for edge in report["edges"]:
        sources = {evidence[i]["source"] for i in edge["evidence_ids"] if i in evidence}
        src, dst = values.get(edge["src"], edge["src"]), values.get(edge["dst"], edge["dst"])
        item = {
            "claim": claim_for(src, edge["rel"], dst),
            "entity_ids": [edge["src"], edge["dst"]],
            "evidence_ids": list(edge["evidence_ids"]),
            "confidence": confidence_for(len(sources)).value,
        }
        if tiered:
            item["tier"] = finding_tier(edge["rel"], src, dst, tiers)
        rebuilt.append(item)
    if tiered:
        rebuilt.sort(key=lambda f: FINDING_TIERS.index(f["tier"]))  # stable: relation order within a tier
    return rebuilt


def summarise_findings(findings: list[dict]) -> dict[str, int]:
    return {tier: sum(1 for f in findings if f.get("tier") == tier) for tier in FINDING_TIERS}
