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


class _Run:
    """The state shared by the stages of one run: where evidence goes, the budget, the clock and the time left."""

    def __init__(self, store: Store, scan_id: int, budget: Budget, config: ActiveConfig, summary: dict) -> None:
        self.store, self.scan_id, self.budget, self.config, self.summary = store, scan_id, budget, config, summary
        self.limits = config.limits
        self.deadline = Deadline(config.limits.deadline_s)
        self.slots = asyncio.Semaphore(config.limits.concurrency)

    def stopped(self) -> str | None:
        if self.deadline.expired:
            return "deadline"
        if self.budget.exhausted:
            return "connection cap"
        return None

    def note_stop(self, reason: str) -> None:
        self.summary.setdefault("stopped", reason)

    def done(self, module: str, ip: str, evidence: Evidence, **extra) -> None:
        record(self.store, self.scan_id, evidence)
        self.store.append_audit(self.scan_id, {"event": "ok", "module": module, "entity": f"ip:{ip}", "evidence_ids": [evidence.id], **extra})

    def failed(self, module: str, ip: str, event: str, reason: str, **extra) -> None:
        self.store.append_audit(self.scan_id, {"event": event, "module": module, "entity": f"ip:{ip}", "reason": reason, **extra})

    async def call(self, module: str, ip: str, probe, **extra) -> Evidence | None:
        """Run one probe (`probe` builds the coroutine) under the concurrency limit and the run's deadline; record its
        evidence, or why there is none."""
        from scrutator.active.net import ProbeRefused

        async with self.slots:
            reason = self.stopped()
            if reason:
                self.note_stop(reason)
                self.failed(module, ip, "skipped", reason, **extra)
                return None
            try:
                evidence = await asyncio.wait_for(probe(), max(0.1, self.deadline.remaining()))
            except asyncio.TimeoutError:
                self.note_stop("deadline")
                self.failed(module, ip, "cancelled", "deadline", **extra)
                return None
            except ProbeRefused as exc:
                self.failed(module, ip, "denied", str(exc), **extra)
                return None
            except Exception as exc:  # noqa: BLE001 - a probe that breaks is recorded, the run goes on
                self.failed(module, ip, "error", f"{type(exc).__name__}: {exc}"[:200], **extra)
                return None
        if evidence is None:  # the cap was reached between the check and the connection
            self.note_stop("connection cap")
            self.failed(module, ip, "skipped", "connection cap", **extra)
            return None
        self.done(module, ip, evidence, **extra)
        return evidence


async def _probe(store: Store, scan_id: int, plan: Plan, budget: Budget, config: ActiveConfig, summary: dict) -> None:
    run = _Run(store, scan_id, budget, config, summary)
    states = await _tcp_stage(run, plan)
    summary["tcp"] = {state: sum(1 for v in states.values() if v == state) for state in sorted(set(states.values()))}
    await asyncio.gather(_tls_stage(run, plan, states), _web_stage(run, plan, states))


async def _tcp_stage(run: _Run, plan: Plan) -> dict[tuple[str, int], str]:
    """One connect check (with banner) for every planned (address, port). Returns the state of each."""
    from scrutator.active.tcpcheck import tcp_check

    states: dict[tuple[str, int], str] = {}

    async def one(ip: str, port: int) -> None:
        evidence = await run.call("tcp", ip, lambda: tcp_check(ip, port, limits=run.limits, budget=run.budget, relax=run.config.relax), port=port)
        if evidence is not None:
            states[(ip, port)] = json.loads(evidence.payload)["state"]

    jobs = [one(t["ip"], p["port"]) for t in plan.targets for p in t["ports"]]
    await asyncio.gather(*jobs)
    return states


async def _tls_stage(run: _Run, plan: Plan, states: dict[tuple[str, int], str]) -> None:
    """A handshake with each in-scope name on every open TLS port (port 443: every name; other ports: the first), and the two
    legacy-protocol attempts once per open TLS port."""
    from scrutator import active
    from scrutator.active.tlscheck import LEGACY, legacy_probe, tls_handshake

    kw = {"limits": run.limits, "budget": run.budget, "relax": run.config.relax}
    jobs = []
    for target in plan.targets:
        ip, names = target["ip"], target["probe_names"]
        for port in active.TLS_PORTS:
            if states.get((ip, port)) != "open":
                continue
            for sni in names if port == active.HTTPS_PORT else names[:1]:
                jobs.append(run.call("tls", ip, lambda ip=ip, port=port, sni=sni: tls_handshake(ip, port, sni, **kw), port=port, sni=sni))
            for version in LEGACY:
                jobs.append(run.call("tls", ip, lambda ip=ip, port=port, v=version: legacy_probe(ip, port, v, names[0], **kw), port=port, legacy=version))
    await asyncio.gather(*jobs)


async def _web_stage(run: _Run, plan: Plan, states: dict[tuple[str, int], str]) -> None:
    """One `GET /` for each in-scope name on an open port 80 (plain) and an open port 443 (TLS). Nothing else is requested."""
    from scrutator import active
    from scrutator.active.httpcheck import http_get

    kw = {"limits": run.limits, "budget": run.budget, "relax": run.config.relax}
    jobs = []
    for target in plan.targets:
        ip = target["ip"]
        for port, tls in ((active.HTTP_PORT, False), (active.HTTPS_PORT, True)):
            if states.get((ip, port)) != "open":
                continue
            for name in target["probe_names"]:
                jobs.append(run.call("http", ip, lambda ip=ip, port=port, name=name, tls=tls: http_get(ip, port, name, tls, **kw), port=port, name=name))
    await asyncio.gather(*jobs)
