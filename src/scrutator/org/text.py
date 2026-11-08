"""Text handling shared by the organisation sources: free text from a registry or a repository is untrusted, may carry an
e-mail address, and may name hosts. Nothing here reads the network or a clock."""

import re
from urllib.parse import urlsplit

from scrutator.model.canonical import canonical_host

MAX_TEXT = 300  # a description longer than this is cut: the section shows what an organisation says about itself, briefly
_EMAIL = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_HOST = re.compile(r"(?<![A-Za-z0-9@._-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63})(?![A-Za-z0-9-])")
ADDRESS_REMOVED = "[address removed]"


def scrub(text: object, limit: int = MAX_TEXT) -> str:
    """Free text as it may be stored: a string, e-mail addresses replaced, control characters dropped, cut to `limit`."""
    if not isinstance(text, str):
        return ""
    cleaned = _EMAIL.sub(ADDRESS_REMOVED, text)
    cleaned = "".join(ch if ch.isprintable() else " " for ch in cleaned)
    cleaned = " ".join(cleaned.split())
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 3] + "..."


def without_addresses(text: str) -> str:
    return _EMAIL.sub(" ", text)


def hosts_in(text: object, roots: set[str] | frozenset[str]) -> list[str]:
    """Host names under one of `roots` (the scope's domains) written in `text`, sorted, without e-mail domains."""
    if not isinstance(text, str) or not roots:
        return []
    found: set[str] = set()
    for match in _HOST.finditer(without_addresses(text)):
        try:
            name = canonical_host(match.group(1).lower().rstrip("."))
        except ValueError:
            continue
        if any(name == root or name.endswith("." + root) for root in roots):
            found.add(name)
    return sorted(found)


def url_host(url: object) -> str:
    """The lower-case host of an http(s) URL, or ""."""
    if not isinstance(url, str):
        return ""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return ""
    if parts.scheme not in ("http", "https"):
        return ""
    return (parts.hostname or "").lower().rstrip(".")


def in_roots(host: str, roots) -> bool:
    return bool(host) and any(host == root or host.endswith("." + root) for root in roots)
