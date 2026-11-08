"""The organisation phase's shared state (`ctx.cache["org"]`).

The modules of the organisation phase run in a fixed order on the seed apex. Earlier ones write what they learn here so
later ones can use it without asking a service twice: the legal names (each with the evidence that produced it), the LEI,
and the GitHub organisation account. Nothing here is a person; a legal name is kept only with a marker that it names an
organisation (an RDAP `org` vCard property, a Wikidata organisation item, a GLEIF record, or the user's `--legal-name`).
"""

import secrets
from dataclasses import dataclass, field

from scrutator.modules._names import usable_org

ORG_CACHE = "org"


@dataclass(frozen=True)
class LegalName:
    name: str
    evidence: str  # how it was found, for the report ("RDAP registrant of example.com", "Wikidata Q###", "--legal-name")
    evidence_ids: tuple[str, ...] = ()


@dataclass
class OrgState:
    seed: str
    roots: frozenset[str]
    explicit_legal_name: str | None = None
    github_org_override: str | None = None
    code_leaks: bool = False
    token_present: bool = False
    names: list[LegalName] = field(default_factory=list)
    lei: str | None = None
    github_org: str | None = None  # resolved account login
    # a per-run random salt so a code-leak fingerprint cannot be reversed or matched across runs; never stored
    leak_salt: bytes = field(default_factory=lambda: secrets.token_bytes(16))

    def add_name(self, name: object, evidence: str, evidence_ids: tuple[str, ...] = ()) -> str | None:
        """Record a legal name if it is a usable organisation name and new. Returns the stored name, or None."""
        usable = usable_org(name)
        if usable is None:
            return None
        for existing in self.names:
            if existing.name.casefold() == usable.casefold():
                return existing.name
        self.names.append(LegalName(usable, evidence, evidence_ids))
        return usable

    def known_names(self) -> list[str]:
        return [n.name for n in self.names]


def get_state(ctx) -> OrgState | None:
    cache = getattr(ctx, "cache", None)
    return cache.get(ORG_CACHE) if isinstance(cache, dict) else None
