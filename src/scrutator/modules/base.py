from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import ClassVar, Protocol

import httpx

from scrutator.model import Entity, EntityType, Evidence


class Mode(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"


class ModuleError(Exception):
    """A source failed or returned something unusable. The engine records it and moves on."""


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


class Module(ABC):
    name: ClassVar[str]
    accepts: ClassVar[frozenset[EntityType]]
    mode: ClassVar[Mode] = Mode.PASSIVE
    needs_key: ClassVar[str | None] = None
    concurrency: ClassVar[int] = 2
    timeout: ClassVar[float] = 60.0

    @abstractmethod
    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation | Fact]: ...
