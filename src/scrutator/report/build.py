import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from scrutator import __version__
from scrutator.attribution import attribute
from scrutator.exposure import exposure
from scrutator.findings import build_findings
from scrutator.packs import PackSet, load_packs
from scrutator.risk.engine import analyze
from scrutator.store import Store


def source_health(store: Store, scan_id: int) -> dict[str, dict[str, Any]]:
    """Per data source: how many runs succeeded, failed, were denied or skipped, how many were
    cancelled by the deadline, whether the circuit breaker marked it down, and the first few
    distinct error messages. A source that failed or was marked down is a gap in coverage."""
    health: dict[str, dict[str, Any]] = {}
    for record in store.audit_log(scan_id):
        module = record.get("module")
        if not module:
            continue
        entry = health.setdefault(
            module, {"ok": 0, "error": 0, "denied": 0, "skipped": 0, "cancelled": 0, "down": False, "errors": []}
        )
        event = record.get("event")
        if event in ("ok", "error", "denied", "skipped", "cancelled"):
            entry[event] += 1
        message = None
        if event == "error":
            message = record.get("error")
        elif event == "breaker":
            entry["down"] = True
            message = f"marked down after {record.get('after')} consecutive failures: no more calls this scan"
        elif event == "skipped" and str(record.get("reason", "")).startswith("source down"):
            entry["down"] = True
        if message and len(entry["errors"]) < 3 and message not in entry["errors"]:
            entry["errors"].append(message)
    return health


def coverage(store: Store, scan_id: int) -> dict[str, Any]:
    """What the scan could not do: the deadline it ran under, whether it ended the scan early, and
    the sources marked down. Derived from the audit log, so a bundle can be checked against it."""
    limits = _meta_json(store, scan_id, "limits") or {}
    log = store.audit_log(scan_id)
    return {
        "deadline_s": limits.get("deadline_s"),
        "deadline_hit": any(r.get("event") == "deadline" for r in log),
        "sources_down": sorted({r["module"] for r in log if r.get("event") == "breaker"}),
    }


def _meta_json(store: Store, scan_id: int, key: str) -> Any:
    raw = store.get_meta(scan_id, key)
    return json.loads(raw) if raw else None


def scan_packs(store: Store, scan_id: int) -> PackSet:
    """The packs the scan used (recorded with it), or the bundled ones for a scan that predates
    v0.4 or was not started through `run_scan`."""
    recorded = _meta_json(store, scan_id, "packs")
    return PackSet.from_dict(recorded) if recorded else load_packs()


def promotions(records: list[dict]) -> list[dict]:
    """The promotions an audit log records, in order: a candidate the user accepted into scope.
    Reports carry them, and `verify` checks the report against the signed audit log."""
    return [
        {key: record.get(key) for key in ("entity", "score", "band", "evidence_ids", "via", "at", "scope_file")}
        for record in records
        if record.get("event") == "promoted"
    ]


def _leads(store: Store, scan_id: int) -> dict:
    """AI leads and pre-mortems: the verified ones are part of the report, the rest are listed
    apart as unverified, with the reason."""
    def shown(lead: dict) -> dict:
        return {key: lead[key] for key in ("kind", "claim", "entity_ids", "evidence_ids", "check")}

    return {
        "verified": [shown(lead) for lead in store.leads(scan_id, "verified")],
        "rejected": [{**shown(lead), "reason": lead["reason"]} for lead in store.leads(scan_id, "rejected")],
    }


def core_report(store: Store, scan_id: int) -> dict:
    """The part of a report the analyses read: scope, entities, relations and evidence."""
    return {
        "scope": _meta_json(store, scan_id, "scope"),
        "entities": [
            {"id": s.entity.id, "type": s.entity.type.value, "value": s.entity.value, "state": s.state.value}
            for s in store.entities(scan_id)
        ],
        "edges": [
            {"src": e.src, "rel": e.rel, "dst": e.dst, "evidence_ids": list(e.evidence_ids)} for e in store.edges(scan_id)
        ],
        "evidence": {
            ev.id: {"source": ev.source, "request": ev.request, "payload": ev.payload, "collected_at": ev.collected_at}
            for ev in store.evidence_for_scan(scan_id)
        },
    }


def build_report(
    store: Store,
    scan_id: int,
    *,
    generated_at: str | None = None,
    ai_info: dict[str, Any] | None = None,
    packs: PackSet | None = None,
) -> dict:
    seed, started_at = store.get_scan(scan_id)
    core = core_report(store, scan_id)
    entities = store.entities(scan_id)
    edges = store.edges(scan_id)
    findings = build_findings(store, scan_id)
    evidence = core["evidence"]
    if ai_info is None:
        ai_info = _meta_json(store, scan_id, "ai")
    packs = packs if packs is not None else scan_packs(store, scan_id)
    report = {
        "tool": {"name": "scrutator", "version": __version__},
        "scan": {"id": scan_id, "seed": seed, "started_at": started_at},
        "scope": core["scope"],
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": {
            "entities": len(entities),
            "by_type": dict(Counter(s.entity.type.value for s in entities)),
            "by_scope": dict(Counter(s.state.value for s in entities)),
            "edges": len(edges),
            "findings": len(findings),
            "risks": 0,
            "candidates": 0,
            "leads": 0,
        },
        "entities": core["entities"],
        "edges": core["edges"],
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
        "coverage": coverage(store, scan_id),
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
        "promotions": promotions(store.audit_log(scan_id)),
        "leads": _leads(store, scan_id),
    }
    analysis = analyze(report, packs)
    report["risks"] = analysis["risks"]
    report["dependencies"] = analysis["dependencies"]
    report["summary"]["risks"] = len(analysis["risks"])
    report["exposure"] = exposure(report)
    report["attribution"] = attribute(report, packs)
    report["summary"]["leads"] = len(report["leads"]["verified"])
    report["summary"]["candidates"] = sum(1 for c in report["attribution"]["candidates"] if c["band"] != "unlikely")
    return report


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=True)
