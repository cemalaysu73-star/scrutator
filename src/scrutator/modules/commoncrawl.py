import json

import httpx

from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules._names import hosts_from_urls, rel_for
from scrutator.modules.base import Module, ModuleContext, ModuleError, Observation, http_failure
from scrutator.modules.registry import register


# Quick to give up: Common Crawl never connected from some networks, and every retry of a connect
# timeout used to cost about 45 s of the scan.
_TIMEOUT = httpx.Timeout(30.0, connect=8.0)
_ATTEMPTS = {"scrutator_attempts": 2}


@register
class CommonCrawl(Module):
    """Hostnames seen under a domain in the latest Common Crawl index (no key)."""

    name = "commoncrawl"
    accepts = frozenset({EntityType.DOMAIN})
    concurrency = 1
    timeout = 60.0
    priority = 0
    apex_only = True

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation]:
        info = await ctx.http.get(
            "https://index.commoncrawl.org/collinfo.json", timeout=_TIMEOUT, extensions=_ATTEMPTS
        )
        if info.status_code != 200:
            raise http_failure("commoncrawl index list", info.status_code)
        try:
            cdx_api = info.json()[0]["cdx-api"]
        except (ValueError, IndexError, KeyError, TypeError) as exc:
            raise ModuleError("commoncrawl returned no usable index") from exc

        resp = await ctx.http.get(
            cdx_api,
            params={"url": f"*.{entity.value}", "output": "json", "fl": "url", "limit": "500"},
            timeout=_TIMEOUT,
            extensions=_ATTEMPTS,
        )
        if resp.status_code == 404:
            return []
        if resp.status_code != 200:
            raise http_failure("commoncrawl", resp.status_code)

        urls: list[str] = []
        for line in resp.text.splitlines():
            try:
                url = json.loads(line).get("url")
            except (ValueError, AttributeError):
                continue
            if isinstance(url, str):
                urls.append(url)

        request = f"GET {resp.request.url}"
        return [
            Observation(
                Entity(type=EntityType.DOMAIN, value=host),
                rel_for(entity.value, host),
                Evidence.create(self.name, request, json.dumps(samples)),
            )
            for host, samples in sorted(hosts_from_urls(urls, root=entity.value).items())
        ]
