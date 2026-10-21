from scrutator.model import Entity, EntityType
from scrutator.modules._names import name_observations
from scrutator.modules.base import Module, ModuleContext, ModuleError, Observation, SourceUnavailable, http_failure
from scrutator.modules.registry import register

# What the service answers with instead of data (HTTP 200, plain text).
_QUOTA = "api count exceeded"


@register
class HackerTarget(Module):
    """Hostnames HackerTarget's DNS data holds for a domain (`hostsearch`, no key).

    The free tier allows 50 calls a day per IP address (2 per second, 500 lines per answer), shared
    with everything else on that address, so the module asks once per scan, about the apex only. When
    the quota is used up the service says so in the body of a 200 answer; that is recorded as the
    source being unavailable, never read as "no names"."""

    name = "hackertarget"
    name_weight = 2
    accepts = frozenset({EntityType.DOMAIN})
    concurrency = 1
    timeout = 45.0
    priority = 0
    apex_only = True
    licence_note = (
        "HackerTarget's free API allows 50 calls per day per IP address and 500 lines per answer; "
        "see hackertarget.com for its terms."
    )

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation]:
        resp = await ctx.http.get("https://api.hackertarget.com/hostsearch/", params={"q": entity.value})
        if resp.status_code != 200:
            raise http_failure("hackertarget", resp.status_code)
        text = resp.text.strip()
        lowered = text.lower()
        if _QUOTA in lowered:
            raise SourceUnavailable("hackertarget daily quota used up (free tier: 50 calls per day per IP)")
        if lowered.startswith("error"):
            raise ModuleError(f"hackertarget refused the query: {text[:80]}")
        lines: dict[str, str] = {}
        for line in text.splitlines():
            host, _, _address = line.partition(",")
            if host.strip():
                lines[host] = line.strip()
        return name_observations("hackertarget", f"GET {resp.request.url}", entity.value, lines)
