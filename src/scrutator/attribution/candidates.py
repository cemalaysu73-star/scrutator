"""From attribution to scope states: pick the candidates, look at each one passively, once.

Only names the engine found evidence for are selected, at most `max_candidates` of them. A
selected name enters the store in the `candidate` state, which lets the engine run passive modules
on it (DNS, registration and certificate lookups, and the network lookups for the addresses it
resolves to) and nothing else: no active module, no names found through a candidate are followed,
and nothing leaves the candidate state until the user promotes it. The state is only ever raised
by the user.
"""

import asyncio
import json

from scrutator.attribution.engine import attribute
from scrutator.engine import Engine
from scrutator.model import Entity, EntityType, ScopeState
from scrutator.modules.base import Module
from scrutator.modules.registry import select_modules
from scrutator.packs import PackSet
from scrutator.report.build import core_report

SELECT_AT = 0.20  # a name needs at least one counted signal this strong to be looked at
DOMAIN_LOOKUPS = ("dns", "rdap", "crtsh")
ADDRESS_LOOKUPS = ("asn", "rdap")


def _done(engine: Engine, scan_id: int) -> set[tuple[str | None, str | None]]:
    return {
        (record.get("module"), record.get("entity"))
        for record in engine.store.audit_log(scan_id)
        if record.get("event") in ("ok", "error")
    }


async def _lookups(engine: Engine, scan_id: int, modules: list[Module], wanted: tuple[str, ...], entities: list[Entity], done: set) -> None:
    tasks = []
    for entity in entities:
        for module in select_modules(modules, entity.type, allow_active=False):
            if module.name in wanted and (module.name, entity.id) not in done:
                done.add((module.name, entity.id))
                tasks.append(engine.run_module(scan_id, module, entity))
    if tasks:
        await asyncio.gather(*tasks)


async def attribute_scan(
    engine: Engine, scan_id: int, modules: list[Module], packs: PackSet, *, max_candidates: int = 20
) -> list[str]:
    """Select candidates from what the scan found, mark them, enrich them passively. Returns the
    names selected, strongest first."""
    store = engine.store
    first = attribute(core_report(store, scan_id), packs)
    chosen = [c for c in first["candidates"] if c["score"] >= SELECT_AT and c["state"] != "in"][: max(0, max_candidates)]
    entities = []
    for item in chosen:
        entity = Entity(type=EntityType.DOMAIN, value=item["value"])
        if store.upsert_entity(scan_id, entity, ScopeState.CANDIDATE):
            store.append_audit(scan_id, {"event": "candidate", "entity": entity.id, "score": item["score"], "band": item["band"]})
        entities.append(entity)

    done = _done(engine, scan_id)
    await _lookups(engine, scan_id, modules, DOMAIN_LOOKUPS, entities, done)

    # the addresses a candidate resolves to are `linked`: the network lookups may follow, nothing more
    ids = {entity.id for entity in entities}
    addresses = sorted({e["dst"] for e in core_report(store, scan_id)["edges"] if e["rel"] == "resolves_to" and e["src"] in ids and e["dst"].startswith("ip:")})
    await _lookups(engine, scan_id, modules, ADDRESS_LOOKUPS, [Entity(type=EntityType.IP, value=a[3:]) for a in addresses], done)

    store.set_meta(scan_id, "attribution", json.dumps({"selected": [e.id for e in entities], "max_candidates": max_candidates}, sort_keys=True))
    return [entity.value for entity in entities]
