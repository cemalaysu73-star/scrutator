import asyncio
import itertools

import httpx

from scrutator.deadline import Deadline
from scrutator.keys import redact
from scrutator.model import Entity, EntityType, ScopeState
from scrutator import mentions
from scrutator.modules.base import Fact, Mode, Module, ModuleContext, Observation, SourceUnavailable
from scrutator.modules.registry import select_modules
from scrutator.scope import ScopePolicy
from scrutator.store import Store

# What marks a source as not answering, as opposed to refusing one question: a timeout, a broken
# connection, or a module saying so (HTTP 5xx or 429, an exhausted quota).
_SOURCE_FAILURES = (SourceUnavailable, httpx.TransportError, asyncio.TimeoutError, ConnectionError, OSError)
DEFAULT_BREAKER_THRESHOLD = 3
# Lookups whose answers are not read for mentions: the wildcard probe (a random name by design), and the opt-in modules
# that read an organisation's pages or people-related records.
_NOT_MINED = frozenset({"wildcard", "brand"})
_PROBE_PREFIX = "wc-probe-"


class _Slots:
    """A counting semaphore that, when a slot frees up, hands it to the waiting lookup with the best rank at that
    moment (then the oldest), not simply the oldest. Ranks are read when the slot is handed over, so a name that a
    second source confirms while it waits moves up the queue."""

    def __init__(self, size: int) -> None:
        self.free = size
        self._waiters: list[list] = []  # [rank callable, sequence, future]
        self._seq = itertools.count()

    async def acquire(self, rank) -> None:
        if self.free > 0 and not self._waiters:
            self.free -= 1
            return
        future = asyncio.get_running_loop().create_future()
        entry = [rank, next(self._seq), future]
        self._waiters.append(entry)
        try:
            await future
        except asyncio.CancelledError:
            if entry in self._waiters:
                self._waiters.remove(entry)
            elif future.done() and not future.cancelled():
                self.release()  # the slot was handed over as the waiter was cancelled: pass it on
            raise

    def release(self) -> None:
        while self._waiters:
            best = min(self._waiters, key=lambda w: (w[0](), w[1]))
            self._waiters.remove(best)
            if not best[2].done():
                best[2].set_result(None)
                return
        self.free += 1


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
        max_entities: int | None = None,
        timeout_cap: float | None = None,
        mine_mentions: bool = True,
    ) -> None:
        self.store = store
        self.scope = scope
        self.ctx = ctx
        self.allow_active = allow_active
        self.deadline = deadline
        self.breaker_threshold = breaker_threshold  # consecutive failures that mark a source down; 0 = never
        self.deadline_losses = 0  # lookups cancelled or never started because the clock ran out
        # A hard cap on the entities a scan records. One answer can name tens of thousands of hosts (a certificate
        # log of a large zone); past the cap new names are counted in the audit log (`entity_cap`), not recorded.
        self.max_entities = max_entities
        # The longest any one lookup may take, whatever the module allows (`scrutator quick` keeps a slow source from
        # spending its whole budget). A lookup cut by it is a timeout like any other: recorded as an error.
        self.timeout_cap = timeout_cap
        # Read every evidence payload for in-scope names the scan does not know yet (scrutator.mentions).
        self.mine_mentions = mine_mentions
        self._mention_roots: frozenset | None = None
        self._mention_pattern = None
        self._entities: int | None = None  # entities recorded so far, counted once and then kept up to date
        self.entities_dropped = 0
        self.roots: set[str] = set(scope.to_dict()["domains"])
        # Called after every lookup, whatever its outcome, with (module, entity, observations): the observations the
        # lookup recorded, or an empty list when it failed, was skipped or was denied. Listeners only watch (the
        # live name list of `scan` and `quick`); what a scan records never depends on them, and a listener that
        # raises is dropped from the scan rather than allowed to end it.
        self.listeners: list = []
        self._semaphores: dict[str, _Slots] = {}
        # Which sources named each name so far, weighted by how much their naming says it exists (Module.name_weight):
        # while lookups wait for a slot, the best-vouched names are resolved first, so live names come out early.
        # Only the order of lookups depends on it, never what a scan records.
        self._named_by: dict[str, dict[str, int]] = {}
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

    def _mentions(self, scan_id: int, module: Module, entity: Entity, observations: list) -> list[Observation]:
        """In-scope names written inside the evidence this lookup returned that the scan does not know yet
        (scrutator.mentions): each becomes a `mentions` relation of the entity the lookup was about, citing the record
        that contains it. No request is made."""
        if module.name in _NOT_MINED or module.name.startswith("exposure"):
            return []
        roots = frozenset(self.roots)
        if self._mention_roots != roots:
            self._mention_roots, self._mention_pattern = roots, mentions.pattern(set(roots))
        known = {obs.entity.value for obs in observations if isinstance(obs, Observation)}
        found: list[Observation] = []
        seen: set[str] = set()
        for obs in observations:
            evidence = obs.evidence
            if evidence.id in seen:
                continue
            seen.add(evidence.id)
            for name in mentions.mentioned(evidence.payload, set(roots), self._mention_pattern):
                if name in known or name.startswith(_PROBE_PREFIX):
                    continue
                try:
                    target = Entity(type=EntityType.DOMAIN, value=name)
                except ValueError:
                    continue
                if not self.scope.decide_entity(target).allowed or self.store.scope_state(scan_id, target.id) is not None:
                    continue
                known.add(name)
                found.append(Observation(target, "mentions", evidence))
        return found

    def names_settled(self) -> None:
        """The scan has no lookup about a name waiting or running: the names it has are resolved (or failed), and what
        runs now is about addresses. Listeners with an `on_names_settled` method are told once."""
        for listener in list(self.listeners):
            hook = getattr(listener, "on_names_settled", None)
            if callable(hook):
                try:
                    hook()
                except Exception:  # noqa: BLE001
                    self.listeners.remove(listener)

    def _notify(self, module: Module, entity: Entity, observations: list) -> None:
        for listener in list(self.listeners):
            try:
                listener(module, entity, observations)
            except Exception:  # noqa: BLE001 - a display must never end a scan
                self.listeners.remove(listener)

    async def run_module(self, scan_id: int, module: Module, entity: Entity) -> list[Entity]:
        """Run `module` on `entity`. Returns newly discovered or newly promoted entities
        that may be investigated further."""
        recorded: list = []
        try:
            return await self._run_module(scan_id, module, entity, recorded)
        finally:
            if self.listeners:
                self._notify(module, entity, recorded)

    async def _run_module(self, scan_id: int, module: Module, entity: Entity, recorded: list) -> list[Entity]:
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
        slots = self._semaphores.setdefault(key, _Slots(module.concurrency))
        await slots.acquire(lambda: -sum(self._named_by.get(entity.id, {}).values()))
        try:
            return await self._run_held(scan_id, module, entity, recorded, state, key)
        finally:
            slots.release()

    async def _run_held(self, scan_id: int, module: Module, entity: Entity, recorded: list, state, key: str) -> list[Entity]:
        # re-checked once the queue has moved: the breaker or the clock may have changed
        if key in self._down:
            self._audit(
                scan_id, "skipped", module, entity,
                reason=f"source down: {self._down[key]} (marked down after repeated failures)",
            )
            return []
        limit = module.timeout if self.timeout_cap is None else min(module.timeout, self.timeout_cap)
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
            if isinstance(exc, asyncio.TimeoutError) and self.deadline is not None and limit < module.timeout and limit < (self.timeout_cap or module.timeout):
                # the limit was cut to the time left, so the clock ended this call, not the
                # source: results so far are kept
                self.deadline_losses += 1
                self._audit(scan_id, "cancelled", module, entity, reason="deadline")
                return []
            # an error message may quote a URL, and a URL may carry a key: nothing is written unredacted
            detail = redact(str(exc)) or (
                f"no answer within {limit:g} s" if isinstance(exc, asyncio.TimeoutError) else "no detail given"
            )
            self._audit(scan_id, "error", module, entity, error=f"{type(exc).__name__}: {detail}")
            if module.breaker and isinstance(exc, _SOURCE_FAILURES):
                self._count_failure(scan_id, module, entity, f"{type(exc).__name__}: {detail}")
            return []
        self._failures[key] = 0

        if self.mine_mentions:
            observations = [*observations, *self._mentions(scan_id, module, entity, observations)]
        explorable: list[Entity] = []
        evidence_ids: set[str] = set()
        # everything the lookup found is written in one transaction: the store runs on the event loop's
        # thread, so a commit per record stalls every other lookup for as long as the disk takes
        dropped = 0
        observations_kept = len(observations)
        with self.store.batch():
            for obs in observations:
                if isinstance(obs, Fact):
                    self.store.add_evidence(obs.evidence)
                    self.store.add_scan_evidence(scan_id, obs.evidence.id)
                    evidence_ids.add(obs.evidence.id)
                    continue
                if obs.entity == entity:
                    continue
                if self.max_entities is not None and self.store.scope_state(scan_id, obs.entity.id) is None:
                    if self._entities is None:
                        self._entities = self.store.entity_count(scan_id)
                    if self._entities >= self.max_entities:
                        dropped += 1
                        observations_kept -= 1
                        continue
                    self._entities += 1
                self.store.add_evidence(obs.evidence)
                evidence_ids.add(obs.evidence.id)
                if obs.entity.type is EntityType.DOMAIN:
                    self._named_by.setdefault(obs.entity.id, {})[module.name] = getattr(module, "name_weight", 1)
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
            if dropped:
                self.entities_dropped += dropped
                self._audit(scan_id, "entity_cap", module, entity, dropped=dropped, cap=self.max_entities)
        recorded.extend(observations if observations_kept == len(observations) else [
            obs for obs in observations
            if isinstance(obs, Fact) or obs.entity == entity or self.store.scope_state(scan_id, obs.entity.id) is not None
        ])
        return explorable
