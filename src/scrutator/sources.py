"""Which sources a scan may use.

A scan asks a dozen public services about the target. Their terms differ (some free tiers are for
non-commercial use only), some need a key, and some users simply do not want a service to see their
target. The user decides with `--sources` (an allow list), `--exclude-sources` and `--no-noncommercial`;
the decision is a `SourcePolicy`, it is recorded in the report, in the signed bundle's manifest and in the
audit log (the first record of the scan), and `scrutator verify` flags a bundle whose evidence or lookups
contradict it.

A name in the policy is a module's name (`asn`) or the source it belongs to (`ripestat`: both RIPEstat
modules; `dns`: the resolver and the wildcard probe). A source that needs a key is off unless the
environment variable that holds the key is set; that is a reason, not a policy, and it is reported next to
the policy's own reasons.
"""

import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from scrutator.modules.base import Module


class SourceError(ValueError):
    """The policy names a source that does not exist, or nothing at all."""


def _names(module: Module) -> frozenset[str]:
    return frozenset({module.name, module.source or module.name})


def known_names(modules: Iterable[Module]) -> list[str]:
    return sorted({n for m in modules for n in _names(m)})


def _split(text: str | None) -> tuple[str, ...]:
    return tuple(dict.fromkeys(part.strip().lower() for part in (text or "").split(",") if part.strip()))


@dataclass(frozen=True)
class SourcePolicy:
    allow: tuple[str, ...] | None = None  # only these sources (None: every source)
    exclude: tuple[str, ...] = ()
    no_noncommercial: bool = False

    @classmethod
    def parse(
        cls, allow: str | None, exclude: str | None, no_noncommercial: bool, modules: Iterable[Module]
    ) -> "SourcePolicy":
        """From the command-line text. Every name must be a real source: a typo must not silently allow
        (or exclude) nothing."""
        modules = list(modules)
        valid = set(known_names(modules))
        wanted_allow = _split(allow) if allow is not None else None
        wanted_exclude = _split(exclude)
        if wanted_allow is not None and not wanted_allow:
            raise SourceError("--sources is empty: it would run nothing")
        for flag, chosen in (("--sources", wanted_allow or ()), ("--exclude-sources", wanted_exclude)):
            unknown = [n for n in chosen if n not in valid]
            if unknown:
                raise SourceError(
                    f"{flag}: unknown source {', '.join(repr(n) for n in unknown)}. Sources: {', '.join(sorted(valid))}"
                )
        return cls(wanted_allow, wanted_exclude, bool(no_noncommercial))

    def to_dict(self) -> dict:
        return {
            "allow": list(self.allow) if self.allow is not None else None,
            "exclude": list(self.exclude),
            "no_noncommercial": self.no_noncommercial,
        }

    @classmethod
    def from_dict(cls, data: Mapping | None) -> "SourcePolicy":
        if not data:
            return cls()
        allow = data.get("allow")
        return cls(
            tuple(str(n) for n in allow) if allow is not None else None,
            tuple(str(n) for n in data.get("exclude") or ()),
            bool(data.get("no_noncommercial")),
        )

    def restriction(self, module: Module) -> str | None:
        """Why the policy itself (not a missing key) keeps `module` from running, or None."""
        names = _names(module)
        if self.allow is not None and not names & set(self.allow):
            return "not in --sources"
        if names & set(self.exclude):
            return "excluded with --exclude-sources"
        if self.no_noncommercial and module.noncommercial:
            return "non-commercial source (--no-noncommercial)"
        return None

    def reason_disabled(self, module: Module, env: Mapping[str, str] | None = None) -> str | None:
        """Why `module` is off in this scan, or None when it may run."""
        restricted = self.restriction(module)
        if restricted:
            return restricted
        if module.needs_key and not (os.environ if env is None else env).get(module.needs_key):
            return f"needs a key: set {module.needs_key}"
        return None

    def select(
        self, modules: Iterable[Module], env: Mapping[str, str] | None = None
    ) -> tuple[list[Module], dict[str, str]]:
        """(modules that may run, {name: reason} for those that may not)."""
        chosen: list[Module] = []
        disabled: dict[str, str] = {}
        for module in modules:
            reason = self.reason_disabled(module, env)
            if reason:
                disabled[module.name] = reason
            else:
                chosen.append(module)
        return chosen, disabled

    def restricted(self, modules: Iterable[Module]) -> set[str]:
        """Names of the modules this policy forbids, whatever keys are set (what `verify` re-derives)."""
        return {m.name for m in modules if self.restriction(m)}

    def record(self, modules: Iterable[Module], env: Mapping[str, str] | None = None) -> dict:
        """What goes into the report, the manifest and the audit log: the policy and its effect."""
        chosen, disabled = self.select(modules, env)
        return {**self.to_dict(), "enabled": sorted(m.name for m in chosen), "disabled": dict(sorted(disabled.items()))}
