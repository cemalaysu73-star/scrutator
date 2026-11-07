"""The orchestrator of an active confirmation run.

Order of events, all in the signed audit log and the evidence of the scan:

1. before the first lookup of the scan: the authorisation (written by the caller) and `active_confirmation_authorised`
   (what may be done, the limits, the fixed port list, the proxy);
2. after the passive collection: the plan (`ACTIVE PLAN`, an evidence record, and an `active_plan` audit record) is written
   BEFORE the first connection;
3. the probes, one evidence record each (scrutator.active.probes), each followed by an audit record;
4. `active_done` (or `active_interrupted`).

Ctrl-C (or a cancelled task) stops every probe at once, keeps what was recorded and says so in the audit log.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field

from scrutator import proxy as proxy_setting
from scrutator.active import RISKY_PORTS, WEB_PORTS, SOURCES
from scrutator.active.guard import Budget, Limits
from scrutator.active.plan import Plan, plan_active
from scrutator.deadline import Deadline
from scrutator.model import Evidence
from scrutator.packs import PackSet
from scrutator.store import Store


@dataclass(frozen=True)
class ActiveConfig:
    """What `run_scan` is asked to do after the passive collection. `relax` is for tests only (a loopback listener stands in
    for a server); no command-line option, no MCP tool and no bundle can set it, and a run that used it says so in the audit
    log, where `verify` shows it as a warning."""

    limits: Limits = field(default_factory=Limits)
    relax: frozenset[str] = frozenset()


def record(store: Store, scan_id: int, evidence: Evidence) -> Evidence:
    store.add_evidence(evidence)
    store.add_scan_evidence(scan_id, evidence.id)
    return evidence


async def run_active(store: Store, scan_id: int, packs: PackSet, config: ActiveConfig) -> dict:
    """Plan, then probe. Returns a summary (also kept as scan metadata `active`)."""
    from scrutator.report.build import core_report

    limits = config.limits
    plan = plan_active(core_report(store, scan_id), packs, limits, config.relax)
    seed = store.get_scan(scan_id)[0]
    plan_evidence = record(store, scan_id, Evidence.create("active", f"ACTIVE PLAN {seed}", json.dumps(plan.to_dict(), sort_keys=True)))
    store.append_audit(scan_id, {
        "event": "active_plan", "evidence_id": plan_evidence.id,
        "targets": [t["ip"] for t in plan.targets],
        "skipped": [{"ip": s["ip"], "kind": s["kind"]} for s in plan.skipped],
        "connect_checks": sum(len(t["ports"]) for t in plan.targets), "not_planned_for_the_cap": len(plan.over_cap),
    })
    budget = Budget(limits)
    summary = {"plan_evidence_id": plan_evidence.id, "targets": len(plan.targets), "skipped": len(plan.skipped), "connections": 0, "interrupted": False}
    try:
        await _probe(store, scan_id, plan, budget, config, summary)
    except asyncio.CancelledError:
        summary["interrupted"] = True
        store.append_audit(scan_id, {"event": "active_interrupted", "connections": budget.used})
        raise
    finally:
        summary["connections"] = budget.used
        store.set_meta(scan_id, "active", json.dumps(summary, sort_keys=True))
    store.append_audit(scan_id, {"event": "active_done", "connections": budget.used, "cap": limits.max_connections, "stopped": summary.get("stopped")})
    return summary


async def _probe(store: Store, scan_id: int, plan: Plan, budget: Budget, config: ActiveConfig, summary: dict) -> None:
    """The probes themselves (added with the connect, TLS and HTTP checks)."""
    return None
