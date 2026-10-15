import json

from scrutator.agent.runner import AgentStats, run_agent
from scrutator.ai.runtime import AIRuntime
from scrutator.engine import Engine
from scrutator.model import Entity
from scrutator.modules.base import Module, ModuleContext
from scrutator.modules.registry import load_builtin_modules
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
) -> tuple[int, AgentStats]:
    scan_id = store.create_scan(seed.value)
    store.set_meta(scan_id, "scope", json.dumps(scope.to_dict(), sort_keys=True))
    if ai is not None:
        ai.bind(store, scan_id)
    engine = Engine(store, scope, ctx, allow_active=allow_active)
    chosen = load_builtin_modules() if modules is None else modules
    stats = await run_agent(
        engine, scan_id, seed, chosen, ai, max_steps=max_steps, max_entities=max_entities
    )
    return scan_id, stats
