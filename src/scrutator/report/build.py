import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from scrutator import __version__
from scrutator.findings import build_findings
from scrutator.packs import PackSet, load_packs
from scrutator.risk.engine import analyze
from scrutator.store import Store


def source_health(store: Store, scan_id: int) -> dict[str, dict[str, Any]]:
    """Per data source: how many runs succeeded, failed, were denied or skipped, and the
    first few distinct error messages. A source that failed is a gap in coverage."""
    health: dict[str, dict[str, Any]] = {}
    for record in store.audit_log(scan_id):
        module = record.get("module")
        if not module:
            continue
        entry = health.setdefault(
            module, {"ok": 0, "error": 0, "denied": 0, "skipped": 0, "errors": []}
        )
        event = record.get("event")
        if event in ("ok", "error", "denied", "skipped"):
            entry[event] += 1
        if event == "error" and len(entry["errors"]) < 3 and record.get("error") not in entry["errors"]:
            entry["errors"].append(record["error"])
    return health


def _meta_json(store: Store, scan_id: int, key: str) -> Any:
    raw = store.get_meta(scan_id, key)
    return json.loads(raw) if raw else None


def scan_packs(store: Store, scan_id: int) -> PackSet:
    """The packs the scan used (recorded with it), or the bundled ones for a scan that predates
    v0.4 or was not started through `run_scan`."""
    recorded = _meta_json(store, scan_id, "packs")
    return PackSet.from_dict(recorded) if recorded else load_packs()


def build_report(
    store: Store,
    scan_id: int,
    *,
    generated_at: str | None = None,
    ai_info: dict[str, Any] | None = None,
    packs: PackSet | None = None,
) -> dict:
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
    if ai_info is None:
        ai_info = _meta_json(store, scan_id, "ai")
    packs = packs if packs is not None else scan_packs(store, scan_id)
    report = {
        "tool": {"name": "scrutator", "version": __version__},
        "scan": {"id": scan_id, "seed": seed, "started_at": started_at},
        "scope": _meta_json(store, scan_id, "scope"),
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": {
            "entities": len(entities),
            "by_type": dict(Counter(s.entity.type.value for s in entities)),
            "by_scope": dict(Counter(s.state.value for s in entities)),
            "edges": len(edges),
            "findings": len(findings),
            "risks": 0,
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
        "sources": source_health(store, scan_id),
        "summary_statements": [
            {"text": s["text"], "evidence_ids": s["evidence_ids"], "confidence": s["confidence"]}
            for s in store.statements(scan_id, status="verified")
        ],
        "unverified_leads": [
            {"text": s["text"], "reason": s["reason"]} for s in store.statements(scan_id, status="rejected")
        ],
        "hypotheses": store.hypotheses(scan_id),
        "egress": store.egress_log(scan_id),
        "ai": ai_info,
        "packs": packs.to_dict(),
    }
    analysis = analyze(report, packs)
    report["risks"] = analysis["risks"]
    report["dependencies"] = analysis["dependencies"]
    report["summary"]["risks"] = len(analysis["risks"])
    return report


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=True)
