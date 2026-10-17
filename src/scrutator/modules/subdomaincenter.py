import json

from scrutator.model import Entity, EntityType
from scrutator.modules._names import name_observations
from scrutator.modules.base import Module, ModuleContext, ModuleError, Observation, http_failure
from scrutator.modules.registry import register


@register
class SubdomainCenter(Module):
    """Hostnames Subdomain Center (A.R.P. Syndicate) holds for a domain (`api.subdomain.center`, no key).

    Origin, from the service's own description: web-scale crawling, real-time Certificate Transparency
    ingestion, embedding-based correlation and proprietary tooling. Its names are therefore claims:
    the data deliberately includes hosts that never resolve publicly, and a name only this source
    reports stays one source's word until DNS or a certificate says the same. The free anonymous tier
    returns up to 500 names in random order, so when the answer is capped a replay finds only part of
    the recorded names again and reports the rest as changed."""

    name = "subdomaincenter"
    accepts = frozenset({EntityType.DOMAIN})
    concurrency = 1
    timeout = 45.0
    priority = 0
    apex_only = True
    licence_note = (
        "Subdomain Center's terms grant a limited licence for personal, non-commercial use; the free anonymous "
        "tier returns up to 500 names in random order. Its data includes names that do not resolve."
    )

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation]:
        resp = await ctx.http.get("https://api.subdomain.center/", params={"domain": entity.value})
        if resp.status_code != 200:
            raise http_failure("subdomain.center", resp.status_code)
        try:
            names = resp.json()
        except ValueError as exc:
            raise ModuleError("subdomain.center returned invalid JSON") from exc
        if not isinstance(names, list):
            raise ModuleError("subdomain.center returned an unexpected payload")
        slices = {name: json.dumps([name]) for name in names if isinstance(name, str)}
        return name_observations("subdomaincenter", f"GET {resp.request.url}", entity.value, slices)
