"""The engagement file that authorises an organisation-exposure assessment (design D18), and the seed rule.

    organisation: Example Corp
    domains: [example.com]
    authorised_by: {name: A. Person, role: CISO}
    start: 2026-10-01
    end: 2026-12-31
    purpose: External red-team assessment of phishing exposure, engagement 2026-17
    github_orgs: [example]        # optional: public code organisations the organisation itself owns

Without a valid file `scrutator exposure` does not run. The file's sha256, its fields and how the attestation was
confirmed go into the hash-chained audit log (and so into the signed bundle) before any lookup. The seed is always an
organisation's domain listed in the file: a personal name, an e-mail address, a phone number or a social handle is
refused, whatever the file says.
"""

import hashlib
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from scrutator.model.canonical import canonical_host

MAX_BYTES = 64 * 1024
# Public mail providers can never be an engagement's domain (their users are private people, not an organisation's
# staff). The second list catches the providers' country variants (gmx.de, yandex.ru, yahoo.co.uk ...).
PUBLIC_MAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "ymail.com",
    "icloud.com", "me.com", "mac.com", "aol.com", "proton.me", "protonmail.com", "pm.me", "tutanota.com", "tuta.io",
    "mail.com", "zoho.com", "fastmail.com", "qq.com", "163.com", "126.com", "naver.com", "mail.ru", "web.de",
})
_PUBLIC_MAIL_LABELS = frozenset({"gmail", "googlemail", "hotmail", "yahoo", "outlook", "gmx", "yandex", "protonmail", "icloud"})
_GITHUB_ORG = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")


class EngagementError(ValueError):
    """The engagement file is missing, unreadable or invalid, or the seed is not allowed."""


class Authoriser(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=2, max_length=120)
    role: str = Field(min_length=2, max_length=120)


class Engagement(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    organisation: str = Field(min_length=2, max_length=200)
    domains: tuple[str, ...] = Field(min_length=1, max_length=50)
    authorised_by: Authoriser
    start: date
    end: date
    purpose: str = Field(min_length=10, max_length=500)
    github_orgs: tuple[str, ...] = Field(default=(), max_length=5)

    @field_validator("domains")
    @classmethod
    def _domains(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        out = []
        for value in values:
            host = canonical_host(str(value))
            if "." not in host:
                raise ValueError(f"{value!r} is not a domain")
            if host in PUBLIC_MAIL_DOMAINS or host.split(".")[0] in _PUBLIC_MAIL_LABELS:
                # an engagement over a public mail provider would make every private address there a "work address"
                raise ValueError(f"{host} is a public mail provider, not an organisation's own domain")
            out.append(host)
        return tuple(dict.fromkeys(out))

    @field_validator("github_orgs")
    @classmethod
    def _orgs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if not _GITHUB_ORG.match(str(value)):
                raise ValueError(f"{value!r} is not a GitHub organisation name")
        return tuple(str(v).lower() for v in values)

    @model_validator(mode="after")
    def _dates(self) -> "Engagement":
        if self.start > self.end:
            raise ValueError("start is after end")
        return self

    def covers(self, host: str) -> bool:
        """Is `host` one of the engagement's domains or under one?"""
        host = host.lower().rstrip(".")
        return any(host == d or host.endswith("." + d) for d in self.domains)

    def record(self) -> dict:
        """What the audit log and the report carry about the engagement."""
        return {
            "organisation": self.organisation,
            "domains": list(self.domains),
            "authorised_by": {"name": self.authorised_by.name, "role": self.authorised_by.role},
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "purpose": self.purpose,
            "github_orgs": list(self.github_orgs),
        }


@dataclass(frozen=True)
class LoadedEngagement:
    engagement: Engagement
    sha256: str
    path: str


def load_engagement(path: str | Path, *, today: date | None = None) -> LoadedEngagement:
    """Read and validate an engagement file. It must be in force today (start <= today <= end)."""
    target = Path(path)
    try:
        data = target.read_bytes()
    except OSError as exc:
        raise EngagementError(f"cannot read the engagement file {target}: {exc.strerror or exc}") from exc
    if len(data) > MAX_BYTES:
        raise EngagementError("the engagement file is larger than 64 KiB")
    try:
        document = yaml.safe_load(data.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise EngagementError(f"the engagement file is not readable YAML: {exc}") from exc
    if not isinstance(document, dict):
        raise EngagementError("the engagement file must be a mapping")
    try:
        engagement = Engagement.model_validate(document)
    except ValidationError as exc:
        problems = "; ".join(f"{'.'.join(str(p) for p in e['loc']) or 'file'}: {e['msg']}" for e in exc.errors()[:6])
        raise EngagementError(f"the engagement file is not valid: {problems}") from exc
    now = today or date.today()
    if not engagement.start <= now <= engagement.end:
        raise EngagementError(f"the engagement is not in force today ({now.isoformat()}): it runs from {engagement.start} to {engagement.end}")
    return LoadedEngagement(engagement, hashlib.sha256(data).hexdigest(), str(target))


# ------------------------------------------------------------------------------------------- the seed

_EMAIL = re.compile(r"@")
_PHONE = re.compile(r"^[\s+()./-]*(?:\d[\s+()./-]*){6,}$")


def refuse_person(seed: str) -> str:
    """Why `seed` is refused as the seed of an exposure assessment, or "" when it has the shape of a domain. A person is
    never a seed: not a name, not an e-mail address, not a phone number, not a handle."""
    text = seed.strip()
    if not text:
        return "the seed is empty"
    if _EMAIL.search(text):
        return "an e-mail address or a handle is not a seed: give the organisation's domain"
    if _PHONE.match(text):
        return "a phone number is not a seed: give the organisation's domain"
    if re.search(r"\s", text) or "." not in text:
        return "a name is not a seed: give the organisation's domain"
    try:
        canonical_host(text)
    except ValueError:
        return "the seed is not a domain"
    return ""


def check_seed(seed: str, engagement: Engagement) -> str:
    """The canonical seed domain, or EngagementError."""
    problem = refuse_person(seed)
    if problem:
        raise EngagementError(problem)
    host = canonical_host(seed)
    if not engagement.covers(host):
        raise EngagementError(f"{host} is not one of the engagement's domains ({', '.join(engagement.domains)})")
    return host
