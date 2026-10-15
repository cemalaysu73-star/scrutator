"""Deny-by-default scope policy.

Decisions are made on the canonical form of the target. Callers that go on to
contact a target must use that same canonical form (see canonical_host).
"""

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from scrutator.model import Entity, EntityType
from scrutator.model.canonical import canonical_host, canonicalize

_FORBIDDEN = re.compile(r"[\s\\\x00-\x1f\x7f]")
_KEYS = {"domains", "cidrs", "asns"}


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def _deny(reason: str) -> Decision:
    return Decision(False, reason)


class ScopePolicy:
    def __init__(
        self,
        domains: Iterable[str] = (),
        cidrs: Iterable[str] = (),
        asns: Iterable[str | int] = (),
    ) -> None:
        self._domains = tuple(canonical_host(d) for d in domains)
        self._networks = tuple(ipaddress.ip_network(c, strict=False) for c in cidrs)
        self._asns = frozenset(canonicalize(EntityType.ASN, str(a)) for a in asns)

    @classmethod
    def from_file(cls, path: str | Path) -> "ScopePolicy":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError("scope file must be a mapping")
        unknown = set(data) - _KEYS
        if unknown:
            raise ValueError(f"unknown scope keys: {sorted(unknown)}")
        policy = cls(
            domains=data.get("domains") or [],
            cidrs=data.get("cidrs") or [],
            asns=data.get("asns") or [],
        )
        if not (policy._domains or policy._networks or policy._asns):
            raise ValueError("scope is empty: list at least one domain, cidr or asn")
        return policy

    def to_dict(self) -> dict[str, list[str]]:
        """Canonical form, suitable for ScopePolicy(**policy.to_dict()) and for recording
        what a scan was authorised to touch."""
        return {
            "domains": list(self._domains),
            "cidrs": [str(net) for net in self._networks],
            "asns": sorted(self._asns),
        }

    def decide(self, target: str) -> Decision:
        if not isinstance(target, str) or not target.strip() or _FORBIDDEN.search(target):
            return _deny("malformed target")
        host = target
        if "://" in target:
            try:
                parts = urlsplit(target)
                host = parts.hostname or ""
            except ValueError:
                return _deny("malformed url")
            if parts.scheme not in ("http", "https") or not host:
                return _deny("unsupported url")
            if "@" in parts.netloc:
                return _deny("userinfo in url is not allowed")
        elif any(c in target for c in "/@?#"):
            return _deny("malformed target")

        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is not None:
            for net in self._networks:
                if net.version == ip.version and ip in net:
                    return Decision(True, f"ip in {net}")
            return _deny("ip not in scope")

        try:
            host = canonical_host(host)
        except ValueError:
            return _deny("invalid hostname")
        for domain in self._domains:
            if host == domain or host.endswith("." + domain):
                return Decision(True, f"host under {domain}")
        return _deny("host not in scope")

    def decide_entity(self, entity: Entity) -> Decision:
        if entity.type in (EntityType.DOMAIN, EntityType.IP):
            return self.decide(entity.value)
        if entity.type is EntityType.ASN:
            if entity.value in self._asns:
                return Decision(True, "asn listed in scope")
            return _deny("asn not in scope")
        return Decision(True, "informational entity")
