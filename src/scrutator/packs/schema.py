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
KINDS = ("providers", "takeover", "signals")
CATEGORIES = ("dns", "mail", "cdn", "hosting", "ca")

_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_VERSION = re.compile(r"^\d{4}\.\d{1,2}\.\d{1,3}$")
_SIGNAL = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,80}$")

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


FILE_MODELS = {"providers": ProvidersFile, "takeover": TakeoverFile, "signals": SignalsFile}
ENTRY_MODELS = {"providers": ProviderEntry, "takeover": TakeoverEntry, "signals": SignalEntry}
