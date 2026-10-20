"""Brand presence: which platform accounts an organisation publishes on its own site, whether they exist, and whether
look-alike handles of its brand exist on those platforms.

Two halves. The collection is the `brand` module (modules/brand.py, `scan --brand`). This file is the derivation: a pure
function of a report's own evidence and the knowledge packs (`platforms`), like the risks and the findings, so
`scrutator verify` re-derives the section from a bundle and compares (check `brand derivable`).

What the evidence holds (all recorded by the module, source `brand`):

- `ROBOTS <url>`: the status and text of robots.txt for a host of the site.
- `PAGE <url>`: a page of the organisation's site that robots.txt allowed: its status, the hops followed and the links to
  known platforms found on it. The page itself is not kept.
- `PROFILE <url>`: the HTTP status of a public profile page (and the host a redirect pointed at). Nothing from the page.

What it may conclude, per handle, from the platform entry's rules: `exists`, `absent`, or `unverifiable` (any other
status, a redirect, an error, or a platform whose page does not tell). Never a guess. Two risk rules read the result
(risk/brand.py): a handle the brand would own that nobody has registered, and a look-alike handle that exists,
ownership unknown. Both are low confidence: a profile page status is all there is.

The brand name is the first label of the scope domain the module ran on (`example` for `example.com`). It is never
free text: the module cannot be pointed at a person's name or username.
"""

import json
import re
from typing import Any
from urllib.parse import urlsplit

from scrutator.packs import PackSet
from scrutator.packs.schema import PlatformEntry

SOURCE = "brand"
MAX_LOOKALIKES = 20  # look-alike handles checked per platform

_HOMOGLYPHS = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5", "m": "rn", "w": "vv", "g": "q"}
_AFFIXES = (
    ("suffix", "{b}official"), ("suffix", "{b}_official"), ("suffix", "{b}hq"), ("suffix", "{b}_hq"), ("suffix", "{b}app"),
    ("suffix", "{b}support"), ("suffix", "{b}_support"), ("suffix", "{b}help"), ("suffix", "{b}team"), ("suffix", "{b}inc"),
    ("prefix", "official{b}"), ("prefix", "official_{b}"), ("prefix", "the{b}"), ("prefix", "real{b}"), ("prefix", "get{b}"),
    ("prefix", "join{b}"), ("prefix", "team{b}"),
    ("separator", "{b}_"), ("separator", "_{b}"), ("separator", "{b}-"), ("separator", "{b}."), ("separator", "{b}__"),
)
_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm")


def _neighbours(char: str) -> list[str]:
    """Keys next to `char` on a QWERTY keyboard, in the same row."""
    for row in _ROWS:
        index = row.find(char)
        if index >= 0:
            return [row[i] for i in (index - 1, index + 1) if 0 <= i < len(row)]
    return []


def lookalikes(brand: str) -> list[tuple[str, str]]:
    """Look-alike handles of a brand name, as (handle, how it was made), deterministic and capped. The classes take
    turns (homoglyph, affix, separator, keyboard typo) so a cap keeps every class. Never the brand itself."""
    brand = brand.lower()
    classes: dict[str, list[tuple[str, str]]] = {"homoglyph": [], "affix": [], "separator": [], "keyboard": []}
    for index, char in enumerate(brand):
        if char in _HOMOGLYPHS:
            classes["homoglyph"].append((brand[:index] + _HOMOGLYPHS[char] + brand[index + 1 :], f"homoglyph {char}->{_HOMOGLYPHS[char]}"))
    if "rn" in brand:
        classes["homoglyph"].append((brand.replace("rn", "m", 1), "homoglyph rn->m"))
    for kind, pattern in _AFFIXES:
        classes["separator" if kind == "separator" else "affix"].append((pattern.format(b=brand), f"{kind} {pattern.replace('{b}', '…')}"))
    for index, char in enumerate(brand):
        for near in _neighbours(char):
            classes["keyboard"].append((brand[:index] + near + brand[index + 1 :], f"keyboard {char}->{near}"))
        if index + 1 < len(brand) and brand[index] != brand[index + 1]:
            swapped = brand[:index] + brand[index + 1] + brand[index] + brand[index + 2 :]
            classes["keyboard"].append((swapped, f"transposition {brand[index]}{brand[index + 1]}"))
        if len(brand) > 3:
            classes["keyboard"].append((brand[:index] + brand[index + 1 :], f"omission {char}"))
        classes["keyboard"].append((brand[:index] + char + brand[index:], f"repetition {char}"))
    out: dict[str, str] = {}
    queues = [list(v) for v in classes.values()]
    while any(queues):
        for queue in queues:
            while queue:
                handle, how = queue.pop(0)
                if handle != brand and handle not in out:
                    out[handle] = how
                    break
    return list(out.items())


# ------------------------------------------------------------------------------------------- reading links


def _path_handle(path: str, template: str) -> str | None:
    """The handle in `path` if it has the shape of `template` ("/@{handle}"), else None. A trailing slash is allowed."""
    prefix, _, suffix = template.partition("{handle}")
    path = path.rstrip("/") if path != "/" else path
    suffix = suffix.rstrip("/")
    if not path.startswith(prefix) or (suffix and not path.endswith(suffix)):
        return None
    middle = path[len(prefix) : len(path) - len(suffix) if suffix else None]
    return middle if middle and "/" not in middle else None


def valid_handle(entry: PlatformEntry, handle: str) -> bool:
    if not entry.handle_min <= len(handle) <= entry.handle_max:
        return False
    allowed = set(entry.handle_chars)
    if any(not (c.isascii() and c.isalnum()) and c not in allowed for c in handle):
        return False
    if entry.no_edge and (handle[0] in entry.no_edge or handle[-1] in entry.no_edge):
        return False
    return handle.lower() not in {r.lower() for r in entry.reserved}


def norm(handle: str) -> str:
    return handle.lower()  # every listed platform treats handles case-insensitively


def parse_link(packs: PackSet, url: str) -> tuple[PlatformEntry, str] | None:
    """The platform and handle a link on the organisation's site points at, or None."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    for entry in packs.platforms:
        if host not in entry.link_hosts:
            continue
        for template in entry.link_paths:
            handle = _path_handle(parts.path, template)
            if handle and valid_handle(entry, handle):
                return entry, norm(handle)
    return None


def profile_url(entry: PlatformEntry, handle: str) -> str:
    return entry.profile.replace("{handle}", handle)


def parse_profile(packs: PackSet, url: str) -> tuple[PlatformEntry, str] | None:
    """The platform and handle of a profile URL the module asked about, or None."""
    for entry in packs.platforms:
        prefix, _, suffix = entry.profile.partition("{handle}")
        if url.startswith(prefix) and url.endswith(suffix):
            handle = url[len(prefix) : len(url) - len(suffix) if suffix else None]
            if handle and valid_handle(entry, handle):
                return entry, handle
    return None


def presence(entry: PlatformEntry, status: Any) -> str:
    """exists, absent or unverifiable, from the status a profile page answered with and the platform's rules."""
    if entry.presence != "status" or not isinstance(status, int) or isinstance(status, bool):
        return "unverifiable"
    if status in entry.exists:
        return "exists"
    if status in entry.absent:
        return "absent"
    return "unverifiable"


def plan(packs: PackSet, brand: str, links: list[str]) -> tuple[list[tuple[PlatformEntry, str]], dict[str, list[tuple[str, str, str]]]]:
    """From the links a site publishes: the official accounts (platform, handle), and per status-checkable platform
    that has one, the handles to ask about as (handle, kind, how): the official handles, the brand name, and up to
    MAX_LOOKALIKES look-alikes of the brand name. Platforms the site does not link to are never asked about."""
    official: list[tuple[PlatformEntry, str]] = []
    for link in links:
        found = parse_link(packs, link)
        if found and found not in official:
            official.append(found)
    checks: dict[str, list[tuple[str, str, str]]] = {}
    for entry in packs.platforms:
        mine = [h for e, h in official if e.id == entry.id]
        if not mine or entry.presence != "status":
            continue
        wanted: list[tuple[str, str, str]] = [(h, "official", "published on the site") for h in mine]
        if valid_handle(entry, brand) and brand not in mine:
            wanted.append((brand, "brand", "the brand name"))
        taken = {h for h, _, _ in wanted}
        count = 0
        for handle, how in lookalikes(brand):
            if count >= MAX_LOOKALIKES:
                break
            if handle not in taken and valid_handle(entry, handle):
                wanted.append((handle, "lookalike", how))
                taken.add(handle)
                count += 1
        checks[entry.id] = wanted
    return official, checks


# ------------------------------------------------------------------------------------------- derivation


def _payload(record: dict) -> dict:
    try:
        value = json.loads(record.get("payload", ""))
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _brand_of(domain: str) -> str:
    return domain.split(".")[0].lower()


_REQUEST = re.compile(r"^(ROBOTS|PAGE|PROFILE|SITE) (\S+)$")


def brand_presence(report: dict, packs: PackSet) -> dict | None:
    """The brand section of a report, derived from its `brand` evidence; None when there is none."""
    evidence = report.get("evidence") or {}
    rows: list[tuple[str, str, str, dict, str]] = []
    for evidence_id, record in sorted(evidence.items()):
        if not isinstance(record, dict) or record.get("source") != SOURCE:
            continue
        match = _REQUEST.match(str(record.get("request", "")))
        if match:
            rows.append((match.group(1), match.group(2), evidence_id, _payload(record), str(record.get("collected_at", ""))))
    if not rows:
        return None
    scope_domains = [str(d) for d in (report.get("scope") or {}).get("domains", [])]
    domains: list[dict] = []
    for kind, target, evidence_id, payload, _ in rows:
        if kind != "SITE" or target in [d["domain"] for d in domains]:
            continue
        if not any(target == root or target.endswith("." + root) for root in scope_domains):
            continue  # a site outside the bundle's own scope is not described
        domains.append({"domain": target, "brand": _brand_of(target), "evidence_id": evidence_id, "robots": [], "pages": [], "official": [], "checks": []})
    by_domain = {d["domain"]: d for d in domains}

    def owner(url: str) -> dict | None:
        host = (urlsplit(url).hostname or "").lower()
        best = None
        for domain in by_domain:
            if host == domain or host.endswith("." + domain):
                if best is None or len(domain) > len(best):
                    best = domain
        return by_domain.get(best) if best else None

    profiles: dict[str, tuple[str, dict]] = {}
    for kind, target, evidence_id, payload, _ in rows:
        if kind == "ROBOTS" and (site := owner(target)) is not None:
            status = payload.get("status")
            text = payload.get("text") if isinstance(payload.get("text"), str) else ""
            home = f"https://{urlsplit(target).hostname}/"
            site["robots"].append({"url": target, "status": status, "allows_home": robots_allows_safe(status, text, home), "evidence_id": evidence_id})
        elif kind == "PAGE" and (site := owner(target)) is not None:
            links = [str(link) for link in payload.get("links", []) if isinstance(link, str)] if isinstance(payload.get("links"), list) else []
            site["pages"].append({"url": target, "status": payload.get("status"), "links": len(links), "evidence_id": evidence_id, "_links": links})
        elif kind == "PROFILE":
            profiles[target] = (evidence_id, payload)

    unverifiable_platforms: set[str] = set()
    for site in domains:
        links = [link for page in site["pages"] for link in page["_links"]]
        page_ids = {page["evidence_id"] for page in site["pages"] if page["_links"]}
        official, checks = plan(packs, site["brand"], links)
        for entry, handle in official:
            url = profile_url(entry, handle)
            cited = sorted(i for i in page_ids if any(parse_link(packs, link) == (entry, handle) for page in site["pages"] if page["evidence_id"] == i for link in page["_links"]))
            if entry.presence != "status":
                state, reason = "unverifiable", "the platform's profile page does not tell (not requested)"
                unverifiable_platforms.add(entry.id)
            elif url in profiles:
                state = presence(entry, profiles[url][1].get("status"))
                reason = _reason(state, profiles[url][1])
                cited.append(profiles[url][0])
            else:
                state, reason = "unchecked", "no profile check was recorded"
            site["official"].append({"platform": entry.id, "handle": handle, "url": url, "state": state, "reason": reason, "evidence_ids": cited})
        for platform_id, wanted in sorted(checks.items()):
            entry = next(e for e in packs.platforms if e.id == platform_id)
            for handle, kind, how in wanted:
                url = profile_url(entry, handle)
                if url not in profiles:
                    continue
                evidence_id, payload = profiles[url]
                state = presence(entry, payload.get("status"))
                site["checks"].append({
                    "platform": platform_id, "handle": handle, "kind": kind, "how": how, "url": url, "state": state,
                    "status": payload.get("status") if isinstance(payload.get("status"), int) else None,
                    "reason": _reason(state, payload), "evidence_id": evidence_id,
                })
        for page in site["pages"]:
            page.pop("_links")
    summary = {
        "official": sum(len(s["official"]) for s in domains),
        "official_absent": sum(1 for s in domains for o in s["official"] if o["state"] == "absent"),
        "brand_unregistered": sum(1 for s in domains for c in s["checks"] if c["kind"] == "brand" and c["state"] == "absent"),
        "lookalikes_checked": sum(1 for s in domains for c in s["checks"] if c["kind"] == "lookalike"),
        "lookalikes_existing": sum(1 for s in domains for c in s["checks"] if c["kind"] == "lookalike" and c["state"] == "exists"),
        "unverifiable": sum(1 for s in domains for c in [*s["official"], *s["checks"]] if c["state"] == "unverifiable"),
    }
    return {"domains": domains, "unverifiable_platforms": sorted(unverifiable_platforms), "summary": summary}


def robots_allows_safe(status: Any, text: str, url: str) -> bool:
    from scrutator.web import robots_allows

    return robots_allows(status if isinstance(status, int) and not isinstance(status, bool) else None, text[:65536], url)


def _reason(state: str, payload: dict) -> str:
    status = payload.get("status")
    if state == "exists":
        return f"the public profile page answered HTTP {status}"
    if state == "absent":
        return f"the public profile page answered HTTP {status} (a suspended or renamed account can answer the same)"
    if payload.get("error"):
        return f"no answer: {str(payload['error'])[:80]}"
    if payload.get("location_host"):
        return f"HTTP {status}: redirected to {str(payload['location_host'])[:80]}, which says nothing about the handle"
    return f"HTTP {status}: the platform's rules do not read this status as present or absent"
