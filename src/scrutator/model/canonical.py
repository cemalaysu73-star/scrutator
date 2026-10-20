"""Canonical forms for entity values. Everything downstream compares canonical strings."""

import ipaddress
import re

from scrutator.model.types import EntityType
from scrutator.textsafe import strip_unsafe

_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
_ASN = re.compile(r"^(?:as)?(\d{1,10})$", re.IGNORECASE)


def canonical_host(value: str) -> str:
    host = value.strip().rstrip(".").lower()
    if not host:
        raise ValueError("empty hostname")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid hostname: {value!r}") from exc
    if len(host) > 253 or not all(_LABEL.match(label) for label in host.split(".")):
        raise ValueError(f"invalid hostname: {value!r}")
    return host


def canonicalize(etype: EntityType, value: str) -> str:
    if etype is EntityType.DOMAIN:
        return canonical_host(value)
    if etype is EntityType.IP:
        return ipaddress.ip_address(value.strip()).compressed
    if etype is EntityType.ASN:
        match = _ASN.match(value.strip())
        if not match:
            raise ValueError(f"invalid ASN: {value!r}")
        return f"AS{int(match.group(1))}"
    if etype is EntityType.ORG:
        # an organisation name comes from a registry or a source answer: control and bidirectional-override
        # characters are dropped so a name can neither steer a terminal nor read differently from what it is
        org = " ".join(strip_unsafe(value).split())
        if not org:
            raise ValueError("empty organisation name")
        return org
    raise ValueError(f"unsupported entity type: {etype}")
