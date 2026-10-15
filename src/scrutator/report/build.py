import json
from collections import Counter
from datetime import datetime, timezone

from scrutator import __version__
from scrutator.findings import build_findings
from scrutator.store import Store


def build_report(store: Store, scan_id: int, *, generated_at: str | None = None) -> dict:
    seed, started_at = store.get_scan(scan_id)
    entities = store.entities(scan_id)
    edges = store.edges(scan_id)
    findings = build_findings(store, scan_id)
    evidence = {
        ev.id: {
            "source": ev.source,
            "request": ev.request,
            "payload": ev.payload,
            "collected_at": ev.collected_at,
        }
        for ev in store.evidence_for_scan(scan_id)
    }
    return {
        "tool": {"name": "scrutator", "version": __version__},
        "scan": {"id": scan_id, "seed": seed, "started_at": started_at},
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": {
            "entities": len(entities),
            "by_type": dict(Counter(s.entity.type.value for s in entities)),
            "by_scope": dict(Counter(s.state.value for s in entities)),
            "edges": len(edges),
            "findings": len(findings),
        },
        "entities": [
            {"id": s.entity.id, "type": s.entity.type.value, "value": s.entity.value, "state": s.state.value}
            for s in entities
        ],
        "edges": [
            {"src": e.src, "rel": e.rel, "dst": e.dst, "evidence_ids": list(e.evidence_ids)} for e in edges
        ],
        "findings": [
            {
                "claim": f.claim,
                "entity_ids": list(f.entity_ids),
                "evidence_ids": list(f.evidence_ids),
                "confidence": f.confidence.value,
            }
            for f in findings
        ],
        "evidence": evidence,
    }


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=True)
