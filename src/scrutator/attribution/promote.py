"""Promotion: the one way a candidate becomes part of the scope.

Only the user's scope file defines what may be investigated, so a promotion writes the name into
that file (keeping a `.bak` copy of the old one), records who asked and on what evidence in the
hash-chained audit log, and only then raises the entity to `in` in the scan. A name that is not a
candidate cannot be promoted, and nothing in Scrutator promotes on its own: the command line asks
for confirmation, and the MCP tool needs an explicit `confirm` argument and is off by default.
"""

import shutil
from datetime import datetime, timezone
from pathlib import Path

import yaml

from scrutator.attribution.engine import attribute
from scrutator.model import Entity, EntityType, ScopeState
from scrutator.report.build import core_report, scan_packs
from scrutator.scope import ScopePolicy
from scrutator.store import Store

_KEYS = {"domains", "cidrs", "asns"}


class PromotionError(ValueError):
    """The promotion was refused; nothing was changed."""


def add_to_scope_file(path: Path, domain: str) -> bool:
    """Add `domain` to the file's `domains` unless a listed domain already covers it. The old file
    is copied to `<name>.bak` first, because rewriting YAML does not keep comments. Returns whether
    the file changed."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise PromotionError(f"cannot read the scope file {path}: {exc}") from exc
    if not isinstance(data, dict) or set(data) - _KEYS:
        raise PromotionError(f"{path} is not a scope file (expected only {sorted(_KEYS)})")
    domains = list(data.get("domains") or [])
    try:
        if domains and ScopePolicy(domains=domains).decide(domain).allowed:
            return False
        ScopePolicy(domains=[domain])
    except ValueError as exc:
        raise PromotionError(f"cannot add {domain!r} to {path}: {exc}") from exc
    domains.append(domain)
    data["domains"] = domains
    try:
        shutil.copy2(path, path.with_name(path.name + ".bak"))
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    except OSError as exc:
        raise PromotionError(f"cannot write the scope file {path}: {exc}") from exc
    return True


def promote(
    store: Store, scan_id: int, entity_id: str, *, scope_file: Path, via: str = "cli", now: str | None = None
) -> dict:
    """Accept a candidate into scope. Returns the audit record (without its `event` key)."""
    state = store.scope_state(scan_id, entity_id)
    if state is None:
        raise PromotionError(f"{entity_id} is not an entity of scan {scan_id}")
    if state is not ScopeState.CANDIDATE or not entity_id.startswith("domain:"):
        raise PromotionError(f"{entity_id} is {state.value}, not a candidate: only candidates can be promoted")
    value = entity_id.removeprefix("domain:")

    item = next((c for c in attribute(core_report(store, scan_id), scan_packs(store, scan_id))["candidates"] if c["entity_id"] == entity_id), None)
    record = {
        "entity": entity_id,
        "score": item["score"] if item else None,
        "band": item["band"] if item else None,
        "evidence_ids": item["evidence_ids"] if item else [],
        "via": via,
        "at": now or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scope_file": scope_file.name,
    }
    add_to_scope_file(scope_file, value)  # first: if the file cannot be written, nothing else changes
    store.append_audit(scan_id, {"event": "promoted", **record})
    store.upsert_entity(scan_id, Entity(type=EntityType.DOMAIN, value=value), ScopeState.IN)
    return record
