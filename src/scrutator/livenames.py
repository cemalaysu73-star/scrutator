"""The live name list: names printed the moment DNS confirms them, while the rest of the scan goes on.

A scan spends most of its time on the addresses its names resolve to (registration data, the announcing network,
InternetDB); the names themselves are usually known and resolved within seconds. This watcher listens to the engine
(`Engine.listeners`) and prints a name as soon as the evidence the report will use says it is live:

- an A or AAAA answer was recorded for it, and
- the wildcard probe of every apex it is under has answered, and its addresses are not all ones a random label under
  that apex also resolves to (the same test as `scrutator.names`, so a name printed here is `live`, and therefore
  `verified`, in the report).

It only watches: nothing a scan records depends on it, and the report is built from the store afterwards exactly as
before. A name it does not print (a claim only a list makes, a name behind a wildcard) is in the report with its tier.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from scrutator.model import EntityType
from scrutator.resolver import parse_payload
from scrutator.scope import ScopePolicy

_WILDCARD = "wildcard"
_DNS = "dns"


class LiveNames:
    """Engine listener. `emit` receives each line (already free of control characters: hostnames and addresses)."""

    def __init__(
        self,
        scope: ScopePolicy,
        roots: set[str],
        emit: Callable[[str], None],
        *,
        probes_expected: bool = True,
        clock: Callable[[], float] = time.monotonic,
        started: float | None = None,
        settled_note: str = "",
    ) -> None:
        self.scope = scope
        self.roots = {r.lower().rstrip(".") for r in roots}
        self.emit = emit
        self.clock = clock
        self.started = clock() if started is None else started
        self.probes_expected = probes_expected
        self.settled_note = settled_note  # said after the names line (what the scan still does)
        self.wild: dict[str, set[str]] = {}  # apex -> addresses its random label resolved to (empty: no wildcard)
        self.pending: dict[str, list[str]] = {}  # name -> addresses, waiting for its apex's probe
        self.printed: dict[str, float] = {}  # name -> seconds after start
        self.named: set[str] = set()  # every in-scope name a source has named
        self.first_subdomain_at: float | None = None
        self.settled_at: float | None = None

    # ------------------------------------------------------------------ engine hooks

    def __call__(self, module, entity, observations) -> None:
        if module.name == _WILDCARD and entity.type is EntityType.DOMAIN:
            addresses: set[str] = set()
            for obs in observations:
                evidence = getattr(obs, "evidence", None)
                if evidence is not None and evidence.request.split(" ")[1:2] in (["A"], ["AAAA"]):
                    answer = parse_payload(evidence.payload)
                    if answer.status == "answer":
                        addresses.update(answer.records)
            self.wild[entity.value] = addresses
            for name in sorted(self.pending):
                self._try(name)
            return
        for obs in observations:
            target = getattr(obs, "entity", None)
            if target is not None and target.type is EntityType.DOMAIN and self._in_scope(target.value):
                self.named.add(target.value)
        if module.name == _DNS and entity.type is EntityType.DOMAIN and self._in_scope(entity.value):
            addresses = sorted(
                {o.entity.value for o in observations if getattr(o, "rel", None) == "resolves_to" and o.entity.type is EntityType.IP}
            )
            if addresses and entity.value not in self.printed:
                self.pending[entity.value] = addresses
                self._try(entity.value)

    def on_names_settled(self) -> None:
        if self.settled_at is not None:
            return
        self.settled_at = self.clock() - self.started
        live = len(self.printed)
        held = len(self.pending)
        other = len(self.named - set(self.printed) - set(self.pending))
        parts = [f"{live} live name{'s' if live != 1 else ''} in {self.settled_at:.1f} s"]
        if held:
            parts.append(f"{held} resolve only to a wildcard address (not proof they exist)")
        if other:
            parts.append(f"{other} more named by sources only (claims until DNS or a certificate agrees; see the report)")
        self.emit("names: " + "; ".join(parts) + "." + (f" {self.settled_note}" if self.settled_note else ""))

    # ------------------------------------------------------------------ helpers

    def _in_scope(self, name: str) -> bool:
        return self.scope.decide(name).allowed

    def _apexes(self, name: str) -> list[str]:
        return [root for root in self.roots if name == root or name.endswith("." + root)]

    def _try(self, name: str) -> None:
        addresses = self.pending.get(name)
        if addresses is None:
            return
        wild: set[str] = set()
        for apex in self._apexes(name):
            if apex == name:
                continue  # the probe is a child of the apex: it says nothing about the apex itself
            if apex not in self.wild:
                if self.probes_expected:
                    return  # the apex's probe has not answered yet: wait, as the report's test needs it
                continue
            wild |= self.wild[apex]
        if wild and set(addresses) <= wild:
            return  # only the wildcard answers for it: the report calls it wildcard-covered, never live
        del self.pending[name]
        at = self.clock() - self.started
        self.printed[name] = at
        if self.first_subdomain_at is None and name not in self.roots:
            self.first_subdomain_at = at
        shown = addresses[0] + (f" +{len(addresses) - 1}" if len(addresses) > 1 else "")
        self.emit(f"  live  {name:<40} {shown:<28} {at:5.1f} s")
