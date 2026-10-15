import json

from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules._names import hosts_from_urls, rel_for
from scrutator.modules.base import Module, ModuleContext, ModuleError, Observation
from scrutator.modules.registry import register


@register
class Wayback(Module):
    """Hostnames seen under a domain in the Internet Archive CDX index (no key)."""

    name = "wayback"
    accepts = frozenset({EntityType.DOMAIN})
    concurrency = 1
    timeout = 90.0

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation]:
        resp = await ctx.http.get(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": f"*.{entity.value}",
                "output": "json",
                "fl": "original",
                "collapse": "urlkey",
                "limit": "500",
            },
        )
        if resp.status_code != 200:
            raise ModuleError(f"wayback returned HTTP {resp.status_code}")
        try:
            rows = resp.json() if resp.text.strip() else []
        except ValueError as exc:
            raise ModuleError("wayback returned invalid JSON") from exc
        if not isinstance(rows, list):
            raise ModuleError("wayback returned an unexpected payload")

        urls = [row[0] for row in rows[1:] if isinstance(row, list) and row and isinstance(row[0], str)]
        request = f"GET {resp.request.url}"
        return [
            Observation(
                Entity(type=EntityType.DOMAIN, value=host),
                rel_for(entity.value, host),
                Evidence.create(self.name, request, json.dumps(samples)),
            )
            for host, samples in sorted(hosts_from_urls(urls, root=entity.value).items())
        ]
