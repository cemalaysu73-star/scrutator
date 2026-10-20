"""`scrutator exposure`: run the organisation-exposure modules for an engagement and record it.

The order is the guarantee: the engagement (its sha256, its fields and how the attestation was confirmed) is written to
the hash-chained audit log before any lookup, right after the source policy; the scope is exactly the engagement's domains; only the four exposure
modules run, each once per domain; and the policy recorded with the scan says they were opted into.
"""

import json
import secrets
from dataclasses import dataclass

from scrutator.deadline import Deadline
from scrutator.engagement import Engagement, LoadedEngagement
from scrutator.engine import Engine
from scrutator.model import Entity, EntityType, ScopeState
from scrutator.modules.base import ModuleContext
from scrutator.modules.registry import load_builtin_modules
from scrutator.orgexposure import SOURCES, Minimiser
from scrutator.packs import PackSet, load_packs
from scrutator.scope import ScopePolicy
from scrutator.sources import SourcePolicy
from scrutator.store import Store


@dataclass
class ExposureRun:
    """What the exposure modules read from the context (ctx.engagement)."""

    engagement: Engagement
    seed: str
    minimiser: Minimiser  # minimiser.detail is the --detail list (None without --detail)


def exposure_scope(engagement: Engagement) -> ScopePolicy:
    return ScopePolicy(domains=list(engagement.domains))


async def run_exposure(
    loaded: LoadedEngagement,
    seed: str,
    store: Store,
    ctx: ModuleContext,
    *,
    confirmed: str,
    detail: bool = False,
    packs: PackSet | None = None,
    deadline_s: float | None = None,
) -> tuple[int, ExposureRun]:
    engagement = loaded.engagement
    scope = exposure_scope(engagement)
    scan_id = store.create_scan(seed)
    packs = packs or load_packs()
    deadline = Deadline(deadline_s) if deadline_s else None
    store.set_meta(scan_id, "limits", json.dumps({"deadline_s": deadline.seconds if deadline else None, "breaker_threshold": 0}, sort_keys=True))
    store.set_meta(scan_id, "scope", json.dumps(scope.to_dict(), sort_keys=True))
    store.set_meta(scan_id, "packs", json.dumps(packs.to_dict(), sort_keys=True))
    modules = [m for m in load_builtin_modules() if m.name in SOURCES]
    policy = SourcePolicy(allow=SOURCES).opt(*SOURCES)
    record = policy.record(load_builtin_modules())
    store.set_meta(scan_id, "source_policy", json.dumps(record, sort_keys=True))
    store.append_audit(scan_id, {"event": "source_policy", **record})  # the first record of every scan's audit log
    store.append_audit(scan_id, {"event": "engagement", "sha256": loaded.sha256, **engagement.record(), "confirmed": confirmed})

    run = ExposureRun(engagement, seed, Minimiser(engagement.covers, secrets.token_bytes(32), [] if detail else None))
    ctx.engagement, ctx.packs = run, packs
    engine = Engine(store, scope, ctx, deadline=deadline, breaker_threshold=0)
    entities = [Entity(type=EntityType.DOMAIN, value=d) for d in engagement.domains]
    with store.batch():
        for entity in entities:
            store.upsert_entity(scan_id, entity, ScopeState.IN)
    for entity in entities:
        for module in modules:
            await engine.run_module(scan_id, module, entity)
    if engine.deadline_losses:
        store.append_audit(scan_id, {"event": "deadline", "seconds": deadline.seconds if deadline else None})
    run.minimiser.key = b""  # the pseudonym key is not needed any more: drop it
    return scan_id, run


DETAIL_FILE = "exposure-detail.json"


def write_detail(store: Store, scan_id: int, run: ExposureRun, loaded: LoadedEngagement, out, *, by: str = "cli"):
    """`--detail`: the person-like work addresses of this run go to their own file (owner-only on POSIX), never into the
    report or the bundle, and an `exposure_detail` record goes into the audit log, which the bundle carries."""
    import os
    from pathlib import Path

    rows = run.minimiser.detail or []
    target = Path(out) / DETAIL_FILE
    target.write_text(json.dumps({"engagement_sha256": loaded.sha256, "scan": scan_id, "addresses": rows}, indent=2, sort_keys=True), encoding="utf-8")
    if os.name == "posix":
        target.chmod(0o600)
    store.append_audit(scan_id, {"event": "exposure_detail", "by": by, "file": target.name, "addresses": len(rows), "engagement_sha256": loaded.sha256})
    return target, rows
