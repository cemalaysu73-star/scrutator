import asyncio
import json
import re
from dataclasses import dataclass
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


def _same_http(old: str, new: str) -> bool:
    if old == new:
        return True
    try:
        return json.loads(old) == json.loads(new)
    except ValueError:
        return False


def _same_dns(old: str, new: str) -> bool:
    return sorted(old.splitlines()) == sorted(new.splitlines())


async def replay_evidence(
    records: list[dict], http: httpx.AsyncClient, resolver: Resolver, *, concurrency: int = 4
) -> list[ReplayResult]:
    """Re-issue each replayable request and say whether the source still returns the same
    thing. Drift is information, not failure: sources change and go down."""
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
                    same = _same_http(rec["payload"], response.text)
                else:
                    answers = await resolver.lookup(parsed[2], parsed[1])
                    same = _same_dns(rec["payload"], "\n".join(answers))
            except Exception as exc:  # noqa: BLE001 - a source being down is a result, not a crash
                return result("unavailable", type(exc).__name__)
        return result("unchanged" if same else "changed")

    return list(await asyncio.gather(*(one(rec) for rec in records)))
