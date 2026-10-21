import json

from scrutator.model import Entity, EntityType
from scrutator.modules._names import name_observations
from scrutator.modules.base import Module, ModuleContext, ModuleError, Observation, SourceUnavailable, http_failure
from scrutator.modules.registry import register

LIMIT = 5000  # names per answer; the service allows up to 50,000 per request


@register
class Thc(Module):
    """Hostnames IP.THC.ORG holds for a domain (`ip.thc.org`, The Hacker's Choice, no key): its subdomain finder over
    an index of DNS data (6 billion+ names, by its own description), as the CSV download of its documented API.

    Added in R6 after a probe on 2026-10-21 (one request about example.com: HTTP 200, a CSV of names). The service
    states it is free without registration or key and documents its API and limits for automated use (a 250-request
    burst per address, refilled at one every two seconds; a download costs three); no separate terms of use were found.
    Its names are claims, like any aggregator's, until DNS or a certificate agrees."""

    name = "thc"
    accepts = frozenset({EntityType.DOMAIN})
    concurrency = 1
    timeout = 45.0
    priority = 0
    apex_only = True
    licence_note = (
        "IP.THC.ORG states it is free, needs no key and will stay free; its documented limit is a 250-request burst "
        "per IP address refilled at 0.5 per second (a CSV download costs 3). No separate terms of use were found."
    )

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation]:
        resp = await ctx.http.get(
            "https://ip.thc.org/api/v1/subdomains/download",
            params={"domain": entity.value, "limit": str(LIMIT), "hide_header": "true"},
        )
        if resp.status_code == 429:
            raise SourceUnavailable("ip.thc.org rate limit reached (HTTP 429)")
        if resp.status_code != 200:
            raise http_failure("ip.thc.org", resp.status_code)
        text = resp.text
        if text.lstrip().startswith(("{", "<")):
            raise ModuleError("ip.thc.org returned something other than a CSV list")
        slices: dict[str, str] = {}
        for line in text.splitlines():
            name = line.split(",", 1)[0].strip().strip('"')
            if name and name.lower() != "subdomain":
                slices[name] = json.dumps([name])
        return name_observations("thc", f"GET {resp.request.url}", entity.value, slices)
