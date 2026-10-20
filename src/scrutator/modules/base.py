from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ClassVar, Protocol

import httpx

from scrutator.model import Entity, EntityType, Evidence


class Mode(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"


class ModuleError(Exception):
    """A source failed or returned something unusable. The engine records it and moves on."""


class SourceUnavailable(ModuleError):
    """The source itself is not answering (HTTP 5xx or 429, a timeout, a refused connection or an
    exhausted quota), as opposed to refusing one particular question. Enough of these in a row
    mark the source down for the rest of the scan."""


def http_failure(source: str, status: int) -> ModuleError:
    """The error for a non-success status: 429 and 5xx mean the source is struggling, anything
    else is an answer about this one question."""
    cls = SourceUnavailable if status == 429 or status >= 500 else ModuleError
    return cls(f"{source} returned HTTP {status}")


class Resolver(Protocol):
    async def lookup(self, name: str, rtype: str) -> list[str]: ...


@dataclass(frozen=True)
class Observation:
    """Edge `input --rel--> entity`, backed by evidence."""

    entity: Entity
    rel: str
    evidence: Evidence


@dataclass(frozen=True)
class Fact:
    """Evidence that belongs to the scan but to no relation: a definite negative result
    ("DNS A ghost.example.com -> NXDOMAIN") or a record that adds no entity. The engine
    stores it with the scan and in the audit log; it creates no edge."""

    evidence: Evidence


@dataclass
class ModuleContext:
    """`http` must follow redirects (RDAP bootstrap relies on it)."""

    http: httpx.AsyncClient
    resolver: Resolver
    # memory shared by the lookups of one scan (the context lives as long as the scan): a module may keep
    # what it learned here so as not to ask a service the same thing twice
    cache: dict = field(default_factory=dict)
    # Only for the opt-in modules that contact the organisation's own site or public profile pages (brand presence,
    # organisation exposure): a client guarded by scrutator.web.WebGuard, and the knowledge packs of the scan.
    web: httpx.AsyncClient | None = None
    packs: Any = None


class Module(ABC):
    name: ClassVar[str]
    accepts: ClassVar[frozenset[EntityType]]
    mode: ClassVar[Mode] = Mode.PASSIVE
    # The environment variable that holds this source's API key (never a command-line option; see scrutator.keys).
    # A module with one is off until the variable is set.
    needs_key: ClassVar[str | None] = None
    concurrency: ClassVar[int] = 2
    timeout: ClassVar[float] = 60.0
    # Lower runs first when the step budget cannot cover everything: resolving names comes before
    # asking an archive about them.
    priority: ClassVar[int] = 50
    # Asked once per apex, not once per discovered name. A source that lists every name under a
    # domain (certificates, archives, passive DNS) already covers every depth with its
    # `*.example.com` query, and registration data belongs to the registered domain: asking again for
    # each subdomain only spends the step budget and the source's rate limit.
    apex_only: ClassVar[bool] = False
    # Modules that talk to the same service share one concurrency limit and one circuit breaker.
    rate_group: ClassVar[str | None] = None
    # False for a module whose failures are the scan's own (the local resolver): the circuit breaker
    # exists to stop calling someone else's service that is not answering.
    breaker: ClassVar[bool] = True
    # A line for module listings and bundles: what the source's terms allow.
    licence_note: ClassVar[str | None] = None
    # True when the source's free tier is for non-commercial (or evaluation) use only, as the README says.
    # `--no-noncommercial` turns these off.
    noncommercial: ClassVar[bool] = False
    # The source this module belongs to when it differs from the module's own name (two modules talking to
    # one service, a probe that is part of DNS): `--sources` and `--exclude-sources` accept either name.
    source: ClassVar[str | None] = None
    # An opt-in module never runs in an ordinary scan: only when the user asks for it with the named flag or command
    # (brand presence: `--brand`; organisation exposure: `scrutator exposure`). The policy records the opt-in.
    opt_in: ClassVar[str | None] = None
    # False when a recorded request cannot be re-issued by `verify --replay` (None: replayable unless keyed).
    replayable: ClassVar[bool | None] = None

    @abstractmethod
    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation | Fact]: ...
