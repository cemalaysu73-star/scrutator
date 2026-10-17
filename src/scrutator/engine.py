import asyncio

import httpx

from scrutator.deadline import Deadline
from scrutator.model import Entity, EntityType, ScopeState
from scrutator.modules.base import Fact, Mode, Module, ModuleContext, SourceUnavailable
from scrutator.modules.registry import select_modules
from scrutator.scope import ScopePolicy
from scrutator.store import Store

# What marks a source as not answering, as opposed to refusing one question: a timeout, a broken
# connection, or a module saying so (HTTP 5xx or 429, an exhausted quota).
_SOURCE_FAILURES = (SourceUnavailable, httpx.TransportError, asyncio.TimeoutError, ConnectionError, OSError)
DEFAULT_BREAKER_THRESHOLD = 3


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
        deadline: Deadline | None = None,
        breaker_threshold: int = DEFAULT_BREAKER_THRESHOLD,
    ) -> None:
        self.store = store
        self.scope = scope
        self.ctx = ctx
        self.allow_active = allow_active
        self.deadline = deadline
        self.breaker_threshold = breaker_threshold  # consecutive failures that mark a source down; 0 = never
        self.deadline_losses = 0  # lookups cancelled or never started because the clock ran out
        self.roots: set[str] = set(scope.to_dict()["domains"])
        self._semaphores: dict[str, asyncio.Semaphore] = {}
        self._failures: dict[str, int] = {}
        self._down: dict[str, str] = {}  # breaker key -> the module that tripped it

    # ------------------------------------------------------------------ what may run

    def add_root(self, entity: Entity) -> None:
        """A name the user asked about is an apex even when the scope is wider than it."""
        if entity.type is EntityType.DOMAIN:
            self.roots.add(entity.value)

    def applies(self, module: Module, entity: Entity) -> bool:
        """Sources that list every name under a domain are asked about the apex only."""
        if module.apex_only and entity.type is EntityType.DOMAIN:
            return entity.value in self.roots
        return True

    def runnable(self, modules: list[Module], entity: Entity) -> list[Module]:
        return [
            m
            for m in select_modules(modules, entity.type, allow_active=self.allow_active)
            if self.applies(m, entity)
        ]

    @property
    def expired(self) -> bool:
        return self.deadline is not None and self.deadline.expired

    @staticmethod
    def _key(module: Module) -> str:
        return module.rate_group or module.name

    def source_down(self, module: Module) -> bool:
        return self._key(module) in self._down

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

    def _count_failure(self, scan_id: int, module: Module, entity: Entity, last_error: str) -> None:
        key = self._key(module)
        self._failures[key] = self._failures.get(key, 0) + 1
        if self.breaker_threshold and self._failures[key] >= self.breaker_threshold and key not in self._down:
            self._down[key] = module.name
            self._audit(
                scan_id, "breaker", module, entity,
                after=self._failures[key], last_error=last_error, group=key,
            )

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

        key = self._key(module)
        semaphore = self._semaphores.setdefault(key, asyncio.Semaphore(module.concurrency))
        async with semaphore:
            # re-checked once the queue has moved: the breaker or the clock may have changed
            if key in self._down:
                self._audit(
                    scan_id, "skipped", module, entity,
                    reason=f"source down: {self._down[key]} (marked down after repeated failures)",
                )
                return []
            limit = module.timeout
            if self.deadline is not None:
                left = self.deadline.remaining()
                if left <= 0:
                    self.deadline_losses += 1
                    self._audit(scan_id, "skipped", module, entity, reason="deadline")
                    return []
                limit = min(limit, left)
            try:
                observations = await asyncio.wait_for(module.run(entity, self.ctx), limit)
            except Exception as exc:  # noqa: BLE001 - a failing source must not abort the scan
                if isinstance(exc, asyncio.TimeoutError) and limit < module.timeout:
                    # the limit was cut to the time left, so the clock ended this call, not the
                    # source: results so far are kept
                    self.deadline_losses += 1
                    self._audit(scan_id, "cancelled", module, entity, reason="deadline")
                    return []
                detail = str(exc) or (
                    f"no answer within {limit:g} s" if isinstance(exc, asyncio.TimeoutError) else "no detail given"
                )
                self._audit(scan_id, "error", module, entity, error=f"{type(exc).__name__}: {detail}")
                if isinstance(exc, _SOURCE_FAILURES):
                    self._count_failure(scan_id, module, entity, f"{type(exc).__name__}: {detail}")
                return []
            self._failures[key] = 0

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
