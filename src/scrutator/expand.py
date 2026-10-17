import asyncio
from dataclasses import dataclass

from scrutator.engine import Engine
from scrutator.model import Entity, ScopeState
from scrutator.modules.base import Module


@dataclass
class ExpandStats:
    rounds: int = 0
    modules_run: int = 0
    entities: int = 0


async def expand(
    engine: Engine,
    scan_id: int,
    seed: Entity,
    modules: list[Module],
    *,
    max_rounds: int = 10,
    max_entities: int = 5000,
) -> ExpandStats:
    """Deterministic breadth-first expansion: run every applicable module on every
    explorable entity until nothing new appears. `max_entities` is a soft cap checked
    between rounds."""
    decision = engine.scope.decide_entity(seed)
    if not decision.allowed:
        raise ValueError(f"seed is out of scope: {decision.reason}")
    engine.store.upsert_entity(scan_id, seed, ScopeState.IN)
    engine.add_root(seed)

    stats = ExpandStats()
    done: set[tuple[str, str]] = set()
    frontier: list[Entity] = [seed]
    for round_no in range(1, max_rounds + 1):
        tasks = []
        for entity in frontier:
            for module in engine.runnable(modules, entity):
                key = (module.name, entity.id)
                if key in done:
                    continue
                done.add(key)
                tasks.append(engine.run_module(scan_id, module, entity))
        if not tasks:
            break
        results = await asyncio.gather(*tasks)
        stats.rounds = round_no
        stats.modules_run += len(tasks)
        frontier = list({e.id: e for found in results for e in found}.values())
        if len(engine.store.entities(scan_id)) >= max_entities or not frontier:
            break
    stats.entities = len(engine.store.entities(scan_id))
    return stats
