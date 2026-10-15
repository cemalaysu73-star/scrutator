"""Hostname helpers shared by the modules that discover hosts."""

import ipaddress
from collections.abc import Iterable
from urllib.parse import urlsplit

from scrutator.model import Entity, EntityType


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
