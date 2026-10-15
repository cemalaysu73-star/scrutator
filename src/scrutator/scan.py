from scrutator.engine import Engine
from scrutator.expand import ExpandStats, expand
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
    modules: list[Module] | None = None,
    max_entities: int = 5000,
    allow_active: bool = False,
) -> tuple[int, ExpandStats]:
    scan_id = store.create_scan(seed.value)
    engine = Engine(store, scope, ctx, allow_active=allow_active)
    chosen = load_builtin_modules() if modules is None else modules
    stats = await expand(engine, scan_id, seed, chosen, max_entities=max_entities)
    return scan_id, stats
