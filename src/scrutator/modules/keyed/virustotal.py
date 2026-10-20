import json

from scrutator.model import Entity, EntityType
from scrutator.modules._names import name_observations
from scrutator.modules.base import Module, ModuleContext, ModuleError, Observation
from scrutator.modules.keyed._common import api_key, failure
from scrutator.modules.registry import register

MAX_PAGES = 5  # 40 names a page: the public API allows 4 requests a minute
_KEPT = ("last_dns_records_date", "last_modification_date")


@register
class VirusTotal(Module):
    """Subdomains VirusTotal holds for a domain: `GET /api/v3/domains/{domain}/subdomains` with the key in the
    `x-apikey` header, following `meta.cursor`. Its names are claims until DNS or a certificate agrees.

    Implemented against the documented API, not live-verified (no key was available)."""

    name = "virustotal"
    accepts = frozenset({EntityType.DOMAIN})
    needs_key = "SCRUTATOR_VIRUSTOTAL_KEY"
    concurrency = 1
    timeout = 60.0
    priority = 0
    apex_only = True
    rate_group = "virustotal"
    licence_note = (
        "VirusTotal terms depend on the plan your key belongs to; the free public API is limited (4 requests a "
        "minute) and not for commercial products or services. You hold the key, so you hold the licence."
    )

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation]:
        key = api_key(self)
        url = f"https://www.virustotal.com/api/v3/domains/{entity.value}/subdomains"
        params = {"limit": "40"}
        observations: list[Observation] = []
        for _ in range(MAX_PAGES):
            resp = await ctx.http.get(url, params=params, headers={"x-apikey": key})
            if resp.status_code != 200:
                raise failure("virustotal", resp.status_code)
            try:
                data = resp.json()
                rows = data["data"]
            except (ValueError, KeyError, TypeError) as exc:
                raise ModuleError("virustotal returned an unexpected payload") from exc
            if not isinstance(rows, list):
                raise ModuleError("virustotal returned an unexpected payload")
            slices = {}
            for row in rows:
                if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                    continue
                attributes = row.get("attributes") if isinstance(row.get("attributes"), dict) else {}
                slices[row["id"]] = json.dumps({"id": row["id"], **{k: attributes[k] for k in _KEPT if k in attributes}}, sort_keys=True)
            observations += name_observations("virustotal", f"GET {resp.request.url}", entity.value, slices)
            cursor = (data.get("meta") or {}).get("cursor")
            if not cursor:
                break
            params = {"limit": "40", "cursor": str(cursor)}
        return observations
