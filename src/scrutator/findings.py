from scrutator.model import Confidence, Finding
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


def findings_from_report(report: dict) -> list[dict]:
    """Recompute the findings a report must contain from its own entities, edges and
    evidence. A report whose findings differ from this has been altered or is inconsistent."""
    values = {e["id"]: e["value"] for e in report["entities"]}
    evidence = report["evidence"]
    rebuilt = []
    for edge in report["edges"]:
        sources = {evidence[i]["source"] for i in edge["evidence_ids"] if i in evidence}
        rebuilt.append(
            {
                "claim": claim_for(values.get(edge["src"], edge["src"]), edge["rel"], values.get(edge["dst"], edge["dst"])),
                "entity_ids": [edge["src"], edge["dst"]],
                "evidence_ids": list(edge["evidence_ids"]),
                "confidence": confidence_for(len(sources)).value,
            }
        )
    return rebuilt
