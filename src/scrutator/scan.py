import asyncio
import json

from scrutator.agent.runner import AgentStats, run_agent
from scrutator.ai.runtime import AIRuntime
from scrutator.attribution.candidates import attribute_scan
from scrutator.deadline import Deadline
from scrutator.engine import DEFAULT_BREAKER_THRESHOLD, Engine
from scrutator.model import Entity
from scrutator.modules.base import Module, ModuleContext
from scrutator.modules.registry import load_builtin_modules
from scrutator.packs import PackSet, load_packs
from scrutator.scope import ScopePolicy
from scrutator.sources import SourcePolicy
from scrutator.store import Store


async def run_scan(
    seed: Entity,
    scope: ScopePolicy,
    store: Store,
    ctx: ModuleContext,
    *,
    ai: AIRuntime | None = None,
    modules: list[Module] | None = None,
    max_steps: int = 60,
    max_entities: int = 5000,
    allow_active: bool = False,
    packs: PackSet | None = None,
    attribution: bool = False,
    max_candidates: int = 20,
    playbooks: bool = True,
    deadline_s: float | None = None,
    deadline: Deadline | None = None,
    breaker_threshold: int = DEFAULT_BREAKER_THRESHOLD,
    source_policy: SourcePolicy | None = None,
) -> tuple[int, AgentStats]:
    """Run a scan. With a deadline (seconds, or a `Deadline` shared with the caller) the scan
    always returns in time: lookups still running when it passes are cancelled, nothing new
    starts, and what was collected so far is kept and reported with the gap recorded."""
    if deadline is None and deadline_s is not None:
        deadline = Deadline(deadline_s)
    scan_id = store.create_scan(seed.value)
    store.set_meta(
        scan_id, "limits",
        json.dumps({"deadline_s": deadline.seconds if deadline else None, "breaker_threshold": breaker_threshold}, sort_keys=True),
    )
    packs = packs or load_packs()
    store.set_meta(scan_id, "scope", json.dumps(scope.to_dict(), sort_keys=True))
    # the knowledge the risk rules will use is recorded with the scan, so a report made months
    # later (or on another machine) is built from the same data
    store.set_meta(scan_id, "packs", json.dumps(packs.to_dict(), sort_keys=True))
    if ai is not None:
        ai.bind(store, scan_id)
    engine = Engine(
        store, scope, ctx, allow_active=allow_active, deadline=deadline, breaker_threshold=breaker_threshold,
        max_entities=max_entities,
    )
    chosen = load_builtin_modules() if modules is None else modules
    # which sources may run is the user's decision (and which have a key): recorded first, in the audit log too,
    # so a bundle can be checked against it
    policy = source_policy or SourcePolicy()
    record = policy.record(chosen)
    chosen, _ = policy.select(chosen)
    store.set_meta(scan_id, "source_policy", json.dumps(record, sort_keys=True))
    store.append_audit(scan_id, {"event": "source_policy", **record})

    async def collect() -> AgentStats:
        warm = getattr(ctx.resolver, "warm_up", None) if ctx is not None else None
        if callable(warm):
            await warm()  # rank the name servers by speed before hundreds of lookups start at once
        stats = await run_agent(
            engine, scan_id, seed, chosen, ai, max_steps=max_steps, max_entities=max_entities,
            playbooks=packs.playbooks if playbooks else (),
        )
        if attribution and not engine.expired:
            await attribute_scan(engine, scan_id, chosen, packs, max_candidates=max_candidates)
        return stats

    try:
        # The engine ends every lookup at the deadline by itself; this outer limit is for what it
        # cannot see (a planner that never answers). A short grace lets the engine finish first.
        stats = await asyncio.wait_for(collect(), deadline.remaining() + 2.0 if deadline else None)
    except asyncio.TimeoutError:
        stats = AgentStats(deadline_hit=True, entities=len(store.entities(scan_id)))
    stats.deadline_hit = stats.deadline_hit or engine.deadline_losses > 0
    if stats.deadline_hit:
        store.append_audit(scan_id, {"event": "deadline", "seconds": deadline.seconds if deadline else None})
    return scan_id, stats
