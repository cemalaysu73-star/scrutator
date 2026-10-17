import json

from scrutator.model import Entity, EntityType
from scrutator.modules._names import name_observations, under
from scrutator.modules.base import Module, ModuleContext, ModuleError, Observation, http_failure
from scrutator.modules.registry import register

MAX_SCANS_PER_HOST = 3  # the most recent scans of a host are enough as evidence


def _slice(row: dict) -> dict:
    """Metadata of one public scan: when, which scan, and what served the page. No screenshot, no page
    content, no title: those are third-party submissions."""
    task, page = row.get("task") or {}, row.get("page") or {}
    return {
        "task": {k: task[k] for k in ("time", "uuid") if k in task},
        "page": {k: page[k] for k in ("domain", "ip", "asn", "server", "status") if k in page},
    }


@register
class UrlScan(Module):
    """Hostnames urlscan.io has scanned under a domain, and what served them (public search, no key).

    The query is on the scanned page (`page.apexDomain` / `page.domain`), not on `domain:`, which also
    matches every page that merely contacted the domain. Anonymous search is limited to 30 requests a
    minute; the module makes one."""

    name = "urlscan"
    accepts = frozenset({EntityType.DOMAIN})
    concurrency = 1
    timeout = 45.0
    priority = 0
    apex_only = True
    licence_note = (
        "urlscan.io's anonymous search is rate limited (30 per minute) and the scans are submitted by third "
        "parties; only metadata is kept. See urlscan.io for its terms before commercial or bulk use."
    )

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation]:
        query = f"page.apexDomain:{entity.value} OR page.domain:{entity.value}"
        resp = await ctx.http.get("https://urlscan.io/api/v1/search/", params={"q": query, "size": "100"})
        if resp.status_code != 200:
            raise http_failure("urlscan", resp.status_code)
        try:
            data = resp.json()
        except ValueError as exc:
            raise ModuleError("urlscan returned invalid JSON") from exc
        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list):
            raise ModuleError("urlscan returned an unexpected payload")

        by_host: dict[str, list[dict]] = {}
        for row in results:
            if not isinstance(row, dict):
                continue
            host = (row.get("page") or {}).get("domain")
            if not isinstance(host, str) or not under(entity.value, host.strip().lower()):
                continue
            bucket = by_host.setdefault(host.strip().lower(), [])
            if len(bucket) < MAX_SCANS_PER_HOST:
                bucket.append(_slice(row))
        payloads = {host: json.dumps(rows, sort_keys=True) for host, rows in by_host.items()}
        return name_observations("urlscan", f"GET {resp.request.url}", entity.value, payloads)
