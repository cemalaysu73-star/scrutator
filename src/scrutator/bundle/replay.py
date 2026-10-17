import asyncio
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any
from urllib.parse import urlsplit

import httpx

from scrutator.model.canonical import canonical_host
from scrutator.modules.base import Resolver
from scrutator.resolver import lookup_status

# The hosts the built-in modules query. A bundle is untrusted input: replay may only ever
# contact these, so a hostile bundle cannot turn a verifier into a request forwarder.
ALLOWED_HTTP_HOSTS = frozenset(
    {
        "crt.sh",
        "rdap.org",
        "stat.ripe.net",
        "web.archive.org",
        "index.commoncrawl.org",
        "api.certspotter.com",
        "api.hackertarget.com",
        "api.subdomain.center",
        "urlscan.io",
        "api.mnemonic.no",
        "internetdb.shodan.io",
    }
)
_DNS = re.compile(r"DNS (A|AAAA|CNAME|MX|NS|TXT|CAA) (\S+)")

# Top-level response-envelope fields that differ on every call and say nothing about the data
# (RIPEstat adds timings, a query id and the answering server to every reply).
_VOLATILE = frozenset({"process_time", "query_id", "server_id", "time", "cached", "version", "build_version"})
# RDAP boilerplate, at any depth: self-links (ARIN echoes an arbitrary address from the queried
# network), notices, remarks and the port-43 hint. Registration dates, name servers, registrars
# and network names are facts and are kept.
_RDAP_NOISE_KEYS = frozenset({"links", "notices", "remarks", "port43"})
_RDAP_STAMP = "last update of rdap database"


@dataclass(frozen=True)
class ReplayResult:
    evidence_id: str
    source: str
    request: str
    status: str  # unchanged, changed, unavailable, skipped
    detail: str = ""


def parse_request(request: str) -> tuple[str, ...] | None:
    """Turn a recorded request into something replayable, or None. Accepts HTTPS GETs to the
    allowlisted source hosts and plain DNS lookups; refuses everything else."""
    if request.startswith("GET "):
        url = request[4:]
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            return None
        if (
            parts.scheme == "https"
            and parts.hostname in ALLOWED_HTTP_HOSTS
            and parts.username is None
            and port in (None, 443)
        ):
            return ("http", url)
        return None
    match = _DNS.fullmatch(request)
    if match:
        try:
            return ("dns", match.group(1), canonical_host(match.group(2)))
        except ValueError:
            return None
    return None


@lru_cache(maxsize=8)
def _loads_any(text: str) -> Any:
    """A JSON document, or newline-delimited JSON as a list, or None."""
    try:
        return json.loads(text)
    except ValueError:
        pass
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except ValueError:
            return None
    return rows or None


def _denoise(value: Any) -> Any:
    """Drop RDAP boilerplate that changes on every call, at any depth."""
    if isinstance(value, dict):
        return {k: _denoise(v) for k, v in value.items() if k not in _RDAP_NOISE_KEYS}
    if isinstance(value, list):
        return [
            _denoise(v)
            for v in value
            if not (isinstance(v, dict) and str(v.get("eventAction", "")).lower() == _RDAP_STAMP)
        ]
    return value


# Counters and clocks that move on every call for a record that is still true: a passive-DNS row
# that was seen again has a later "last seen" and a higher count. They are kept in the evidence as
# information, but a replay does not read their change as the fact having changed.
_ROW_VOLATILE = frozenset({"lastSeenTimestamp", "lastUpdatedTimestamp", "times"})


def _members(value: Any) -> list[Any]:
    """Every node of a live response, at any depth, so a recorded URL string matches a live row such
    as ["http://..."] (Wayback) or {"url": "http://..."} (Common Crawl), and a recorded slice of a
    nested row (urlscan, passive DNS) matches the row inside the envelope it came in."""
    found: list[Any] = []

    def walk(node: Any) -> None:
        found.append(node)
        if isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, dict):
            for item in node.values():
                walk(item)

    walk(value)
    return found


@lru_cache(maxsize=8)
def _live_members(text: str) -> list[Any]:
    """The nodes of one live response, computed once however many records are checked against it."""
    return _members(_loads_any(text))


def _subset(recorded: Any, live: Any) -> bool:
    """Is everything the evidence says still in this live node? A recorded dict is a slice: its keys
    must be present with the same values (nested slices recursively); extra live keys are fine."""
    if isinstance(recorded, dict):
        return isinstance(live, dict) and all(
            k in live and _subset(v, live[k]) for k, v in recorded.items() if k not in _ROW_VOLATILE
        )
    if isinstance(recorded, list):
        return isinstance(live, list) and all(any(_subset(r, item) for item in live) for r in recorded)
    return recorded == live


def _contains(recorded: Any, live: list[Any]) -> bool:
    if isinstance(recorded, dict):
        return any(_subset(recorded, row) for row in live if isinstance(row, dict))
    return recorded in live


def supports(old: str, new: str) -> bool:
    """Does the live response still say what the recorded payload says? Evidence for a
    hostname can be a slice of a longer response, and some sources add per-call noise, so
    equality is the wrong test. Equal text, equal JSON (ignoring volatile envelope fields and
    RDAP boilerplate), a recorded array whose elements are all still present, or contained
    plain text all count."""
    if old == new:
        return True
    old_json, new_json = _loads_any(old), _loads_any(new)
    if old_json is None or new_json is None:
        return old in new
    if isinstance(old_json, dict) and isinstance(new_json, dict):
        strip = lambda d: _denoise({k: v for k, v in d.items() if k not in _VOLATILE})  # noqa: E731
        return strip(old_json) == strip(new_json)
    if isinstance(old_json, list):
        if not old_json:
            return new_json == old_json
        live = _live_members(new)
        return all(_contains(item, live) for item in old_json)
    return old_json == new_json


def _same_dns(old: str, new: str) -> bool:
    return sorted(old.splitlines()) == sorted(new.splitlines())


async def replay_evidence(
    records: list[dict], http: httpx.AsyncClient, resolver: Resolver, *, concurrency: int = 4
) -> list[ReplayResult]:
    """Re-issue each replayable request and say whether the source still supports the
    recorded evidence. Drift is information, not failure: sources change and go down."""
    semaphore = asyncio.Semaphore(concurrency)
    fetches: dict[str, asyncio.Future] = {}  # url -> (status, text): each distinct request is sent once

    async def fetch(url: str) -> tuple[int, str]:
        if url not in fetches:
            async def get() -> tuple[int, str]:
                async with semaphore:
                    response = await http.get(url)
                return response.status_code, response.text

            fetches[url] = asyncio.ensure_future(get())
        return await fetches[url]

    async def one(rec: dict) -> ReplayResult:
        def result(status: str, detail: str = "") -> ReplayResult:
            return ReplayResult(rec["id"], rec["source"], rec["request"], status, detail)

        parsed = parse_request(rec["request"])
        if parsed is None:
            return result("skipped", "request is not replayable")
        try:
            if parsed[0] == "http":
                status, text = await fetch(parsed[1])
                if status != 200:
                    return result("unavailable", f"HTTP {status}")
                same = supports(rec["payload"], text)
            else:
                async with semaphore:
                    answer = await lookup_status(resolver, parsed[2], parsed[1])
                same = _same_dns(rec["payload"], answer.payload())
        except Exception as exc:  # noqa: BLE001 - a source being down is a result, not a crash
            return result("unavailable", type(exc).__name__)
        return result("unchanged" if same else "changed")

    return list(await asyncio.gather(*(one(rec) for rec in records)))
