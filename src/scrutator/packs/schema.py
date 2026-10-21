"""Schema of a knowledge pack file.

A pack is a YAML file: a small envelope (schema number, kind, calendar version, date) and a
list of entries. Everything is validated with pydantic and unknown keys are errors, so a typo
in a contribution fails loudly in CI instead of silently matching nothing.
"""

import re
from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from scrutator.model.canonical import canonical_host

SCHEMA_VERSION = 1
# KINDS are the files the risk and attribution results are derived from: the report embeds them and
# `verify` re-derives from them, so they are hashed together. Playbooks only guide the agent; no
# result depends on them, so they are loaded and validated like the rest but kept out of that hash.
KINDS = ("providers", "takeover", "signals", "platforms")
ALL_KINDS = (*KINDS, "playbooks", "compliance")
# kinds added after bundles already existed: a bundle made before a kind existed declares no file of it, and is
# compared with a trusted copy without that kind (it cannot have used it)
NEWER_KINDS = frozenset({"platforms"})
SITUATIONS = ("cname_out", "san_cohabitants", "mail", "delegated", "ip_without_network", "candidates", "spf_includes")
CATEGORIES = ("dns", "mail", "cdn", "hosting", "ca")

_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_VERSION = re.compile(r"^\d{4}\.\d{1,2}\.\d{1,3}$")
_SIGNAL = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,80}$")
_MODULE = re.compile(r"^[a-z][a-z0-9_]{0,30}$")

# which match lists make sense for which category: a mail entry has no business listing
# an ASN, and an ns pattern in a CDN entry is a mistake worth catching in review
_ALLOWED_MATCHES = {
    "dns": {"ns"},
    "mail": {"mx", "spf"},
    "cdn": {"cname", "asn"},
    "hosting": {"cname", "asn"},
    "ca": {"issuer"},
}


def host_pattern(value: str) -> str:
    """A lower-case host suffix. A label may contain `*`, which matches inside that label only
    (`awsdns-*.com` matches `ns-1.awsdns-04.com`)."""
    text = str(value).strip().lower().rstrip(".")
    if not text or not text.isascii():
        raise ValueError(f"not an ASCII host pattern: {value!r}")
    canonical_host(text.replace("*", "x"))
    return text


class Entry(BaseModel):
    """Fields every entry has. `verified` means a maintainer checked the patterns against the
    cited `source`; unverified entries are kept visible so they can be checked, not hidden.
    `examples` are real-looking values the entry must match: the bundled packs are tested
    against their own examples, so every entry carries its own fixture."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    source: str = Field(max_length=300)
    verified: bool
    note: str = Field(default="", max_length=400)
    examples: tuple[str, ...] = Field(default=(), max_length=10)

    @field_validator("id")
    @classmethod
    def _id_shape(cls, value: str) -> str:
        if not _ID.match(value):
            raise ValueError("id must be lower-case letters, digits and hyphens")
        return value

    @field_validator("source")
    @classmethod
    def _source_is_a_url(cls, value: str) -> str:
        if not value.startswith("https://") or re.search(r"\s", value):
            raise ValueError("source must be an https URL")
        return value


class ProviderEntry(Entry):
    provider: str = Field(min_length=1, max_length=80)
    category: Literal["dns", "mail", "cdn", "hosting", "ca"]
    ns: tuple[str, ...] = ()
    mx: tuple[str, ...] = ()
    spf: tuple[str, ...] = ()
    cname: tuple[str, ...] = ()
    asn: tuple[int, ...] = ()
    issuer: tuple[str, ...] = ()

    @field_validator("ns", "mx", "spf", "cname")
    @classmethod
    def _hosts(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(host_pattern(v) for v in values)

    @field_validator("asn")
    @classmethod
    def _asns(cls, values: tuple[int, ...]) -> tuple[int, ...]:
        for v in values:
            if not 1 <= v <= 4294967295:
                raise ValueError(f"not an AS number: {v}")
        return values

    @field_validator("issuer")
    @classmethod
    def _issuers(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        cleaned = tuple(" ".join(v.lower().split()) for v in values)
        if any(len(v) < 4 for v in cleaned):
            raise ValueError("an issuer pattern shorter than 4 characters would match too much")
        return cleaned

    @model_validator(mode="after")
    def _matches_fit_the_category(self) -> "ProviderEntry":
        used = {name for name in ("ns", "mx", "spf", "cname", "asn", "issuer") if getattr(self, name)}
        if not used:
            raise ValueError("an entry needs at least one pattern")
        extra = used - _ALLOWED_MATCHES[self.category]
        if extra:
            raise ValueError(f"category {self.category!r} cannot use {sorted(extra)}")
        return self


class TakeoverEntry(Entry):
    """A service whose hostnames can be claimed by someone else when a CNAME to them dangles.

    `dangling` says how the dangling state shows: `nxdomain` (the target name does not exist,
    which a passive DNS lookup can see) or `http-fingerprint` (the name resolves but the
    service answers with an "unclaimed" page, which needs an active probe and is not done in
    passive mode)."""

    provider: str = Field(min_length=1, max_length=80)
    cname: tuple[str, ...] = Field(min_length=1)
    status: Literal["vulnerable", "edge-case"]
    dangling: Literal["nxdomain", "http-fingerprint"]
    fingerprint: str = Field(default="", max_length=200)

    @field_validator("cname")
    @classmethod
    def _hosts(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(host_pattern(v) for v in values)


class SignalEntry(Entry):
    """How common an attribution signal is across unrelated organisations (used from v0.5)."""

    signal: str
    frequency: float = Field(ge=0.0, le=1.0)
    sample_size: int = Field(ge=1)

    @field_validator("signal")
    @classmethod
    def _signal_shape(cls, value: str) -> str:
        if not _SIGNAL.match(value):
            raise ValueError("signal names are lower-case words, digits and . _ : -")
        return value


class PlaybookEntry(Entry):
    """A short recipe the agent is offered when the investigation is in a situation it describes.

    `when` lists situations that must all hold (see agent/playbooks.py for how each is decided from
    the graph), `steps` are the recipe, `prefer` names the modules whose lookups the recipe is about.
    It guides which lookups the planner ranks first; it can never add an option or widen the scope."""

    title: str = Field(min_length=1, max_length=80)
    when: tuple[str, ...] = Field(min_length=1, max_length=4)
    steps: tuple[str, ...] = Field(min_length=1, max_length=6)
    prefer: tuple[str, ...] = Field(default=(), max_length=4)

    @field_validator("when")
    @classmethod
    def _situations(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        unknown = [v for v in values if v not in SITUATIONS]
        if unknown:
            raise ValueError(f"unknown situation {unknown[0]!r}; known: {list(SITUATIONS)}")
        return values

    @field_validator("steps")
    @classmethod
    def _steps(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if not value.strip() or len(value) > 200:
                raise ValueError("a step is one sentence of at most 200 characters")
        return values

    @field_validator("prefer")
    @classmethod
    def _modules(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if not _MODULE.match(value):
                raise ValueError(f"not a module name: {value!r}")
        return values


FRAMEWORKS = ("iso27001", "nis2", "cis", "owasp", "kvkk")


class ComplianceMapping(BaseModel):
    """One reference of a framework a rule's finding is relevant to. `title` is the author's paraphrase, never the
    framework's text; `verified` means the reference was read at `source` (an authoritative public page)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    framework: Literal["iso27001", "nis2", "cis", "owasp", "kvkk"]
    ref: str = Field(min_length=1, max_length=40)
    title: str = Field(min_length=1, max_length=120)
    verified: bool
    source: str = Field(max_length=300)

    @field_validator("source")
    @classmethod
    def _https(cls, value: str) -> str:
        if not value.startswith("https://") or re.search(r"\s", value):
            raise ValueError("source must be an https URL")
        return value


class ComplianceEntry(Entry):
    """Informational mapping of one risk rule to framework references (packs/data/compliance.yaml). No result of a
    scan depends on it: like playbooks it stays out of the hashed pack content, and the audit shows it as an
    informational mapping, not a certification or a legal conclusion."""

    rule: str = Field(min_length=1, max_length=64)
    mappings: tuple[ComplianceMapping, ...] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def _verified_only_when_every_mapping_is(self) -> "ComplianceEntry":
        if self.verified and not all(m.verified for m in self.mappings):
            raise ValueError("an entry is verified only when every one of its mappings is")
        return self


_HANDLE_PUNCTUATION = set("-_.")


class PlatformEntry(Entry):
    """A public platform an organisation may link to from its own site (brand presence, scrutator/brand.py).

    `profile` builds a profile URL from a handle; `link_hosts` and `link_paths` recognise a link to an account; a handle
    is ASCII letters and digits plus the characters in `handle_chars` (only `-`, `_`, `.`), `handle_min` to `handle_max`
    long, not starting or ending with a character in `no_edge`, and not one of `reserved` (site pages, not accounts).
    These are templates and character sets, not regular expressions, so a pack (or a bundle's embedded copy) cannot
    make matching slow. `presence: status` means the HTTP status of the public profile page tells: `exists` and `absent`
    list the statuses (absent may be empty: then absence is never concluded). `presence: unverifiable` means the page
    does not tell, blocks automated requests, or the platform's terms forbid them: such a platform is never requested."""

    platform: str = Field(min_length=1, max_length=80)
    profile: str = Field(max_length=200)
    link_hosts: tuple[str, ...] = Field(min_length=1, max_length=8)
    link_paths: tuple[str, ...] = Field(min_length=1, max_length=6)
    handle_chars: str = Field(default="", max_length=3)
    handle_min: int = Field(ge=1, le=64)
    handle_max: int = Field(ge=1, le=255)
    no_edge: str = Field(default="", max_length=3)
    reserved: tuple[str, ...] = Field(default=(), max_length=60)
    presence: Literal["status", "unverifiable"]
    exists: tuple[int, ...] = Field(default=(), max_length=5)
    absent: tuple[int, ...] = Field(default=(), max_length=5)

    @field_validator("profile")
    @classmethod
    def _profile(cls, value: str) -> str:
        if not value.startswith("https://") or value.count("{handle}") != 1 or re.search(r"[\s?#]", value):
            raise ValueError("profile must be an https URL template with {handle} once and no query")
        host = value[len("https://"):].split("/", 1)[0]
        canonical_host(host)
        if "{handle}" in host or "/" not in value[len("https://"):]:
            raise ValueError("{handle} must be in the path of the profile URL")
        return value

    @field_validator("link_hosts")
    @classmethod
    def _link_hosts(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(canonical_host(v) for v in values)

    @field_validator("link_paths")
    @classmethod
    def _link_paths(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if not value.startswith("/") or value.count("{handle}") != 1 or not re.fullmatch(r"[a-z0-9/@~_.{}-]+", value):
                raise ValueError(f"a link path is a template such as /@{{handle}}: {value!r}")
        return values

    @field_validator("handle_chars", "no_edge")
    @classmethod
    def _punctuation(cls, value: str) -> str:
        if set(value) - _HANDLE_PUNCTUATION:
            raise ValueError("only -, _ and . may be listed")
        return value

    @field_validator("exists", "absent")
    @classmethod
    def _statuses(cls, values: tuple[int, ...]) -> tuple[int, ...]:
        if any(not 100 <= v <= 599 for v in values):
            raise ValueError("not an HTTP status")
        return values

    @model_validator(mode="after")
    def _presence_rules(self) -> "PlatformEntry":
        if self.handle_min > self.handle_max:
            raise ValueError("handle_min is larger than handle_max")
        if self.presence == "status" and not self.exists:
            raise ValueError("presence: status needs at least one status in exists")
        if self.presence == "unverifiable" and (self.exists or self.absent):
            raise ValueError("presence: unverifiable takes no statuses")
        if set(self.exists) & set(self.absent):
            raise ValueError("a status cannot mean both exists and absent")
        return self


class _Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_version: Literal[1] = Field(alias="schema")
    version: str
    updated: date
    description: str = Field(default="", max_length=300)

    @field_validator("version")
    @classmethod
    def _calendar_version(cls, value: str) -> str:
        if not _VERSION.match(str(value)):
            raise ValueError("version must look like 2026.10.1 (year.month.serial)")
        return str(value)


class ProvidersFile(_Envelope):
    kind: Literal["providers"]
    entries: list[ProviderEntry]


class TakeoverFile(_Envelope):
    kind: Literal["takeover"]
    entries: list[TakeoverEntry]


class SignalsFile(_Envelope):
    kind: Literal["signals"]
    entries: list[SignalEntry]


class PlatformsFile(_Envelope):
    kind: Literal["platforms"]
    entries: list[PlatformEntry]


class ComplianceFile(_Envelope):
    kind: Literal["compliance"]
    entries: list[ComplianceEntry]


class PlaybooksFile(_Envelope):
    kind: Literal["playbooks"]
    entries: list[PlaybookEntry]


FILE_MODELS = {"providers": ProvidersFile, "takeover": TakeoverFile, "signals": SignalsFile, "platforms": PlatformsFile, "playbooks": PlaybooksFile, "compliance": ComplianceFile}
ENTRY_MODELS = {"providers": ProviderEntry, "takeover": TakeoverEntry, "signals": SignalEntry, "platforms": PlatformEntry, "playbooks": PlaybookEntry, "compliance": ComplianceEntry}
