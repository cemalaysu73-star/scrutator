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
}


def _confidence(distinct_sources: int) -> Confidence:
    if distinct_sources >= 3:
        return Confidence.HIGH
    if distinct_sources == 2:
        return Confidence.MEDIUM
    return Confidence.LOW


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
        rel_text = _REL_TEXT.get(edge.rel, edge.rel.replace("_", " "))
        findings.append(
            Finding(
                claim=f"{values.get(edge.src, edge.src)} {rel_text} {values.get(edge.dst, edge.dst)}",
                entity_ids=(edge.src, edge.dst),
                evidence_ids=edge.evidence_ids,
                confidence=_confidence(len(sources)),
            )
        )
    return findings
