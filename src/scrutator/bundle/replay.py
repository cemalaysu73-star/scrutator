import asyncio
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any
from urllib.parse import urlsplit

import httpx

from scrutator.active import SOURCES as ACTIVE_SOURCES
from scrutator.model.canonical import canonical_host
from scrutator.modules.base import Resolver
from scrutator.resolver import lookup_status

# The hosts the built-in modules query. A bundle is untrusted input: replay may only ever
# contact these, so a hostile bundle cannot turn a verifier into a request forwarder.
ALLOWED_HTTP_HOSTS = frozenset(
    {
        "crt.sh",
        "rdap.org",
        # the regional registries' own RDAP servers: public addresses are asked of the one that holds them
        "rdap.arin.net",
        "rdap.db.ripe.net",
        "rdap.apnic.net",
        "rdap.lacnic.net",
        "rdap.afrinic.net",
        "ip.thc.org",
        "stat.ripe.net",
        "web.archive.org",
        "index.commoncrawl.org",
        "api.certspotter.com",
        "api.hackertarget.com",
        "api.subdomain.center",
        "urlscan.io",
        "api.mnemonic.no",
        "internetdb.shodan.io",
        # `scan --org`: the organisation sources whose request is a plain GET and whose STORED payload is a slice of
        # the live response, so a replay can re-compare it (reviewed for R9). These three keep no person data and store
        # the raw answer. The other organisation sources store a minimised projection (to leave out author and
        # maintainer fields) or a status, so they are marked non-replayable and a replay skips them, like keyed sources.
        "api.gleif.org",
        "query.wikidata.org",
        "haveibeenpwned.com",
    }
)
_DNS = re.compile(r"DNS (A|AAAA|CNAME|MX|NS|TXT|CAA) (\S+)")
# crt.sh's public database (the crtsh module's fallback): only this fixed query about one name is ever re-run, never SQL
# from a bundle (scrutator.modules.crtsh.db_query builds it).
_PGSQL = re.compile(r"PGSQL crt\.sh:5432/certwatch identities ([a-z0-9_.-]+)")
# Brand presence asks public profile pages for their HTTP status (scrutator/brand.py). A replay may re-ask, but only these
# hosts (the bundled platforms whose status tells; fixed here, never taken from a bundle's packs) and only a path that
# has the shape of a profile page: one handle, optionally after "@" or "u/", nothing else.
PROFILE_HOSTS = frozenset({"github.com", "gitlab.com", "mastodon.social", "huggingface.co", "codeberg.org", "hub.docker.com"})
_PROFILE_PATH = re.compile(r"/(?:@|u/)?[A-Za-z0-9_][A-Za-z0-9._-]{0,63}/?")

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
    if request.startswith("PROFILE "):
        url = request[len("PROFILE "):]
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            return None
        if (
            parts.scheme == "https" and parts.hostname in PROFILE_HOSTS and parts.username is None and port is None
            and not parts.query and not parts.fragment and _PROFILE_PATH.fullmatch(parts.path) and ".." not in parts.path
            and url == f"https://{parts.hostname}{parts.path}"
        ):
            return ("profile", url)
        return None
    match = _PGSQL.fullmatch(request)
    if match:
        try:
            return ("pgsql", canonical_host(match.group(1)))
        except ValueError:
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


def subject_names(report: dict) -> set[str]:
    """The names a bundle is about: its scope's domains and every name it did not mark out of scope. A DNS replay
    stays inside them (and their children), so a bundle cannot make a verifier look up names of its choosing."""
    names = {str(d) for d in (report.get("scope") or {}).get("domains", [])}
    names |= {e["value"] for e in report.get("entities", []) if e.get("type") == "domain" and e.get("state") != "out"}
    return names


def _inside(name: str, subject: set[str]) -> bool:
    return any(name == root or name.endswith("." + root) for root in subject)


# How much a replay will do. A bundle is untrusted input and its evidence decides the requests: without a bound, a
# bundle of a million records would make the verifier send a million lookups. A large honest scan (the default
# entity cap of 5000 names) holds a few thousand records; these limits leave room for several times that.
MAX_RECORDS = 20_000  # replayable records attempted per replay
MAX_HTTP_REQUESTS = 2_000  # distinct HTTP requests per replay


async def replay_evidence(
    records: list[dict], http: httpx.AsyncClient, resolver: Resolver, *, concurrency: int = 4, subject: set[str] | None = None,
    max_records: int = MAX_RECORDS, max_http: int = MAX_HTTP_REQUESTS,
) -> list[ReplayResult]:
    """Re-issue each replayable request and say whether the source still supports the
    recorded evidence. Drift is information, not failure: sources change and go down.
    With `subject` (see subject_names), DNS lookups of names outside it are skipped. At most `max_records` records
    are attempted and `max_http` distinct HTTP requests sent; the rest are reported as skipped (replay limit)."""
    semaphore = asyncio.Semaphore(concurrency)
    attempted = 0
    urls: set[str] = set()
    fetches: dict[str, asyncio.Future] = {}  # url -> (status, text): each distinct request is sent once

    async def fetch(url: str) -> tuple[int, str]:
        if url not in fetches:
            async def get() -> tuple[int, str]:
                async with semaphore:
                    response = await http.get(url)
                return response.status_code, response.text

            fetches[url] = asyncio.ensure_future(get())
        return await fetches[url]

    queries: dict[str, asyncio.Future] = {}

    async def query_db(domain: str) -> str:
        """crt.sh's database, the fixed query, once per name per replay (see scrutator.modules.crtsh)."""
        if domain not in queries:
            from scrutator import pgwire
            from scrutator.modules.crtsh import DB_HOST, DB_PORT, DB_TIMEOUT, db_query, db_rows

            async def run() -> str:
                async with semaphore:
                    columns, rows = await pgwire.query(DB_HOST, db_query(domain), port=DB_PORT, timeout=DB_TIMEOUT)
                return json.dumps(db_rows(columns, rows), sort_keys=True)

            queries[domain] = asyncio.ensure_future(run())
        return await queries[domain]

    async def one(rec: dict) -> ReplayResult:
        def result(status: str, detail: str = "") -> ReplayResult:
            return ReplayResult(rec["id"], rec["source"], rec["request"], status, detail)

        nonlocal attempted
        if rec["source"] in ACTIVE_SOURCES:
            # a probe of the client's own address, made once under an authorisation: a verifier never contacts a target
            return result("skipped", "active evidence is not replayed")
        parsed = parse_request(rec["request"])
        if parsed is None:
            return result("skipped", "request is not replayable")
        if parsed[0] == "pgsql" and subject is not None and not _inside(parsed[1], subject):
            return result("skipped", "name is outside the bundle's scope and entities")
        if parsed[0] == "dns" and subject is not None and not _inside(parsed[2], subject):
            return result("skipped", "name is outside the bundle's scope and entities")
        if attempted >= max_records:
            return result("skipped", f"replay limit: only the first {max_records} records are replayed")
        if parsed[0] in ("http", "profile") and parsed[1] not in urls:
            if len(urls) >= max_http:
                return result("skipped", f"replay limit: only {max_http} distinct requests are sent")
            urls.add(parsed[1])
        attempted += 1  # no await between the checks and the count: the decision is made in record order
        try:
            if parsed[0] == "profile":
                async with semaphore:
                    response = await http.get(parsed[1], follow_redirects=False)
                try:
                    recorded = json.loads(rec["payload"]).get("status")
                except (ValueError, AttributeError):
                    recorded = None
                return result("unchanged" if recorded == response.status_code else "changed",
                              "" if recorded == response.status_code else f"HTTP {recorded} then, {response.status_code} now")
            if parsed[0] == "pgsql":
                same = supports(rec["payload"], await query_db(parsed[1]))
            elif parsed[0] == "http":
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
