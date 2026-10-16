import asyncio

from scrutator.model import Entity, EntityType, ScopeState
from scrutator.modules.base import Fact, Mode, Module, ModuleContext
from scrutator.scope import ScopePolicy
from scrutator.store import Store


class Engine:
    """Runs one module on one entity. This is the only place modules are executed:
    scope, mode, concurrency, timeout, evidence storage and auditing all live here."""

    def __init__(
        self,
        store: Store,
        scope: ScopePolicy,
        ctx: ModuleContext | None,
        *,
        allow_active: bool = False,
    ) -> None:
        self.store = store
        self.scope = scope
        self.ctx = ctx
        self.allow_active = allow_active
        self._semaphores: dict[str, asyncio.Semaphore] = {}

    def _audit(self, scan_id: int, event: str, module: Module, entity: Entity, **extra) -> None:
        self.store.append_audit(
            scan_id, {"event": event, "module": module.name, "entity": entity.id, **extra}
        )

    def _classify(self, parent_state: ScopeState, rel: str, entity: Entity) -> ScopeState:
        if self.scope.decide_entity(entity).allowed:
            return ScopeState.IN
        if (
            entity.type is EntityType.IP
            and rel == "resolves_to"
            and parent_state in (ScopeState.IN, ScopeState.CANDIDATE)
        ):
            return ScopeState.LINKED
        return ScopeState.OUT

    async def run_module(self, scan_id: int, module: Module, entity: Entity) -> list[Entity]:
        """Run `module` on `entity`. Returns newly discovered or newly promoted entities
        that may be investigated further."""
        state = self.store.scope_state(scan_id, entity.id)
        if state is None or state is ScopeState.OUT:
            self._audit(scan_id, "denied", module, entity, reason="entity is not in scope")
            return []
        if module.mode is Mode.ACTIVE:
            if not self.allow_active:
                self._audit(scan_id, "skipped", module, entity, reason="active mode disabled")
                return []
            if state is not ScopeState.IN:
                self._audit(
                    scan_id, "denied", module, entity, reason="active modules need an in-scope entity"
                )
                return []

        semaphore = self._semaphores.setdefault(module.name, asyncio.Semaphore(module.concurrency))
        async with semaphore:
            try:
                observations = await asyncio.wait_for(module.run(entity, self.ctx), module.timeout)
            except Exception as exc:  # noqa: BLE001 - a failing source must not abort the scan
                self._audit(scan_id, "error", module, entity, error=f"{type(exc).__name__}: {exc}")
                return []

        explorable: list[Entity] = []
        evidence_ids: set[str] = set()
        for obs in observations:
            if isinstance(obs, Fact):
                self.store.add_evidence(obs.evidence)
                self.store.add_scan_evidence(scan_id, obs.evidence.id)
                evidence_ids.add(obs.evidence.id)
                continue
            if obs.entity == entity:
                continue
            self.store.add_evidence(obs.evidence)
            evidence_ids.add(obs.evidence.id)
            child_state = self._classify(state, obs.rel, obs.entity)
            changed = self.store.upsert_entity(scan_id, obs.entity, child_state)
            self.store.add_edge(scan_id, entity.id, obs.rel, obs.entity.id, [obs.evidence.id])
            if changed and child_state is not ScopeState.OUT:
                explorable.append(obs.entity)
        self._audit(
            scan_id,
            "ok",
            module,
            entity,
            observations=len(observations),
            evidence_ids=sorted(evidence_ids),
        )
        return explorable
