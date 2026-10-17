"""Hostname helpers shared by the modules that discover hosts."""

import ipaddress
from collections.abc import Iterable
from urllib.parse import urlsplit

from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules.base import Observation


def rel_for(root: str, name: str) -> str:
    return "has_subdomain" if name.endswith("." + root) else "related_host"


def host_entity(raw: str) -> Entity | None:
    """A DOMAIN entity for `raw`, or None for IPs and anything that is not a hostname."""
    try:
        ipaddress.ip_address(raw.strip())
        return None
    except ValueError:
        pass
    try:
        return Entity(type=EntityType.DOMAIN, value=raw)
    except ValueError:
        return None


def under(root: str, name: str) -> bool:
    return name.endswith("." + root)


def name_observations(
    source: str, request: str, root: str, payloads: dict[str, str], *, only_under: bool = True
) -> list[Observation]:
    """One observation per hostname, each with its own small evidence record (`payloads` maps the
    hostname to the slice of the source's answer that names it). Names that are not hostnames, the
    root itself and, unless asked otherwise, names outside the root are dropped."""
    seen: dict[str, str] = {}
    for raw, payload in payloads.items():
        found = host_entity(raw.strip().lower().removeprefix("*."))
        if found is None or found.value == root or (only_under and not under(root, found.value)):
            continue
        seen.setdefault(found.value, payload)
    return [
        Observation(
            Entity(type=EntityType.DOMAIN, value=name),
            rel_for(root, name),
            Evidence.create(source, request, payload),
        )
        for name, payload in sorted(seen.items())
    ]


def hosts_from_urls(urls: Iterable[str], *, root: str, max_samples: int = 5) -> dict[str, list[str]]:
    """Group URLs by hostname, keeping a few sample URLs per host. Skips `root` itself."""
    hosts: dict[str, list[str]] = {}
    for url in urls:
        try:
            host = urlsplit(url).hostname
        except ValueError:
            continue
        if not host:
            continue
        entity = host_entity(host)
        if entity is None or entity.value == root:
            continue
        samples = hosts.setdefault(entity.value, [])
        if len(samples) < max_samples and url not in samples:
            samples.append(url)
    return hosts


# Registries replace a registrant they must not publish with a placeholder, and privacy services
# put their own name there. A placeholder is not evidence that two domains share an owner. This is
# a short list of the wording seen in practice, not a complete one: a placeholder missing from it
# would be recorded as if it were an organisation.
_PLACEHOLDERS = (
    "redacted", "privacy", "proxy", "withheld", "not disclosed", "data protected", "gdpr",
    "whoisguard", "private registration", "non-public", "statutory masking",
)
_EMPTY = {"", "n/a", "na", "none", "unknown", "-", "null"}


def usable_org(value: object) -> str | None:
    """An organisation name with its whitespace cleaned up, or None for anything that is not a
    real name: a non-string, a redaction placeholder or a privacy service."""
    if not isinstance(value, str):
        return None
    text = " ".join(value.split())
    lowered = text.lower()
    if len(text) < 3 or lowered in _EMPTY or any(word in lowered for word in _PLACEHOLDERS):
        return None
    return text
