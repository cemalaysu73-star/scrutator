"""The organisation phase of a scan (`scan --org`): after the passive collection, run the organisation-scoped sources
on the seed apex, in a fixed order, through the engine (scope gate, audit, evidence like every lookup).

The order lets an earlier source inform a later one without a second request: Wikidata resolves the organisation (its
legal name, its LEI, its GitHub account) before GLEIF and GitHub use them. The legal name may also come from the RDAP
registrant collected in the passive phase, or from `--legal-name`. Every derived name is recorded with its evidence.
"""

import json
from dataclasses import dataclass

from scrutator.engine import Engine
from scrutator.model import Entity, EntityType, ScopeState
from scrutator.modules.base import Module
from scrutator.modules._names import usable_org
from scrutator.org import ORG_PHASE
from scrutator.org.state import ORG_CACHE, OrgState
from scrutator.store import Store

# the fixed run order of the organisation phase
ORG_ORDER = ("wikidata", "gleif", "hibp", "github", "github_leaks", "packages", "handles")
MAX_FRESH_NAMES = 50  # new in-scope names from this phase resolved once each


@dataclass(frozen=True)
class OrgConfig:
    legal_name: str | None = None
    github_org: str | None = None
    code_leaks: bool = False
    self_attested: bool = False  # --self: the person owns/controls the organisation's repositories (for --code-leaks)
    token_present: bool = False


def _registrant_names(store: Store, scan_id: int, seed: str) -> list[tuple[str, tuple[str, ...]]]:
    """Legal-name candidates from the RDAP registrant of the seed apex already collected in the passive phase."""
    out = []
    seed_id = f"domain:{seed}"
    for edge in store.edges(scan_id):
        if edge.src == seed_id and edge.rel == "registrant":
            name = usable_org(edge.dst.split(":", 1)[1] if ":" in edge.dst else edge.dst)
            if name:
                out.append((name, tuple(edge.evidence_ids)))
    return out


async def run_org_phase(
    engine: Engine, scan_id: int, seed: Entity, modules: list[Module], config: OrgConfig, roots: set[str]
) -> None:
    store = engine.store
    state = OrgState(
        seed=seed.value, roots=frozenset(roots),
        explicit_legal_name=config.legal_name, github_org_override=config.github_org,
        code_leaks=config.code_leaks, token_present=config.token_present,
    )
    if config.legal_name:
        state.add_name(config.legal_name, "--legal-name")
    for name, evidence_ids in _registrant_names(store, scan_id, seed.value):
        state.add_name(name, f"RDAP registrant of {seed.value}", evidence_ids)
    if engine.ctx is not None:
        engine.ctx.cache[ORG_CACHE] = state

    store.append_audit(scan_id, {
        "event": "org_phase",
        "legal_names": [{"name": n.name, "evidence": n.evidence} for n in state.names],
        "github_org": config.github_org,
        "code_leaks": config.code_leaks,
    })
    if config.code_leaks:
        # the authorisation for reading the organisation's own repositories for secrets, in the signed log before the lookup
        store.append_audit(scan_id, {
            "event": "self_attestation", "domains": [seed.value], "organisation": config.legal_name or seed.value,
            "confirmed": "--self", "statement": "the person running this scan owns or controls the organisation's public repositories and authorises a bounded secret scan of them",
            "scope": "code-leaks",
        })

    before = {s.entity.id for s in store.entities(scan_id)}
    by_name = {m.name: m for m in modules if getattr(m, "phase", None) == ORG_PHASE}
    for name in ORG_ORDER:
        module = by_name.get(name)
        if module is not None:
            await engine.run_module(scan_id, module, seed)

    # In-scope names first seen in this phase (a repo naming a host) would otherwise stay unresolved claims: the planner
    # has finished. Each is asked of DNS once, through the engine like any lookup, so its tier says whether it exists.
    dns = next((m for m in modules if m.name == "dns"), None)
    if dns is not None:
        fresh = [
            s.entity for s in store.entities(scan_id)
            if s.entity.id not in before and s.entity.type is EntityType.DOMAIN and s.state is ScopeState.IN
        ][:MAX_FRESH_NAMES]
        for entity in fresh:
            await engine.run_module(scan_id, dns, entity)
