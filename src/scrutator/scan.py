import json

from scrutator.agent.runner import AgentStats, run_agent
from scrutator.ai.runtime import AIRuntime
from scrutator.attribution.candidates import attribute_scan
from scrutator.engine import Engine
from scrutator.model import Entity
from scrutator.modules.base import Module, ModuleContext
from scrutator.modules.registry import load_builtin_modules
from scrutator.packs import PackSet, load_packs
from scrutator.scope import ScopePolicy
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
) -> tuple[int, AgentStats]:
    scan_id = store.create_scan(seed.value)
    packs = packs or load_packs()
    store.set_meta(scan_id, "scope", json.dumps(scope.to_dict(), sort_keys=True))
    # the knowledge the risk rules will use is recorded with the scan, so a report made months
    # later (or on another machine) is built from the same data
    store.set_meta(scan_id, "packs", json.dumps(packs.to_dict(), sort_keys=True))
    if ai is not None:
        ai.bind(store, scan_id)
    engine = Engine(store, scope, ctx, allow_active=allow_active)
    chosen = load_builtin_modules() if modules is None else modules
    stats = await run_agent(
        engine, scan_id, seed, chosen, ai, max_steps=max_steps, max_entities=max_entities
    )
    if attribution:
        await attribute_scan(engine, scan_id, chosen, packs, max_candidates=max_candidates)
    return scan_id, stats
