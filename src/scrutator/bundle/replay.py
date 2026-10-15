import asyncio
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from scrutator.model.canonical import canonical_host
from scrutator.modules.base import Resolver

# The hosts the built-in modules query. A bundle is untrusted input: replay may only ever
# contact these, so a hostile bundle cannot turn a verifier into a request forwarder.
ALLOWED_HTTP_HOSTS = frozenset(
    {"crt.sh", "rdap.org", "stat.ripe.net", "web.archive.org", "index.commoncrawl.org"}
)
_DNS = re.compile(r"DNS (A|AAAA|CNAME|MX|NS|TXT) (\S+)")

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


def _members(value: Any) -> list[Any]:
    """The elements of a live response plus the members of its rows, so a recorded URL string
    matches a live row such as ["http://..."] (Wayback) or {"url": "http://..."} (Common Crawl)."""
    items = value if isinstance(value, list) else [value]
    found: list[Any] = []
    for item in items:
        found.append(item)
        if isinstance(item, list):
            found.extend(item)
        elif isinstance(item, dict):
            found.extend(item.values())
    return found


def _contains(recorded: Any, live: list[Any]) -> bool:
    if isinstance(recorded, dict):
        return any(
            isinstance(row, dict) and all(k in row and row[k] == v for k, v in recorded.items())
            for row in live
        )
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
        live = _members(new_json)
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

    async def one(rec: dict) -> ReplayResult:
        def result(status: str, detail: str = "") -> ReplayResult:
            return ReplayResult(rec["id"], rec["source"], rec["request"], status, detail)

        parsed = parse_request(rec["request"])
        if parsed is None:
            return result("skipped", "request is not replayable")
        async with semaphore:
            try:
                if parsed[0] == "http":
                    response = await http.get(parsed[1])
                    if response.status_code != 200:
                        return result("unavailable", f"HTTP {response.status_code}")
                    same = supports(rec["payload"], response.text)
                else:
                    answers = await resolver.lookup(parsed[2], parsed[1])
                    same = _same_dns(rec["payload"], "\n".join(answers))
            except Exception as exc:  # noqa: BLE001 - a source being down is a result, not a crash
                return result("unavailable", type(exc).__name__)
        return result("unchanged" if same else "changed")

    return list(await asyncio.gather(*(one(rec) for rec in records)))
