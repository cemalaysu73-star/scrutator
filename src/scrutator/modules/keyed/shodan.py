import json

from scrutator.model import Entity, EntityType
from scrutator.modules._names import name_observations
from scrutator.modules.base import Module, ModuleContext, ModuleError, Observation
from scrutator.modules.keyed._common import api_key, failure
from scrutator.modules.registry import register

MAX_PAGES = 2  # each page costs one query credit
_KEPT = ("type", "value", "last_seen")


@register
class ShodanDns(Module):
    """DNS records Shodan holds for a domain: `GET /dns/domain/{domain}` (the documented Shodan DNS API). Shodan
    takes the key as the query parameter `key`, so the recorded request is the URL WITHOUT it and errors are
    redacted. The answer has `subdomains` (labels) and `data` rows (subdomain, type, value, last_seen); names
    are claims until DNS or a certificate agrees. Not the keyless InternetDB, which is per address.

    Implemented against the documented API, not live-verified (no key was available)."""

    name = "shodan"
    accepts = frozenset({EntityType.DOMAIN})
    needs_key = "SCRUTATOR_SHODAN_KEY"
    concurrency = 1
    timeout = 60.0
    priority = 0
    apex_only = True
    rate_group = "shodan"
    licence_note = (
        "Shodan terms depend on the plan your key belongs to; each DNS lookup uses a query credit. You hold the "
        "key, so you hold the licence."
    )

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation]:
        key = api_key(self)
        base = f"https://api.shodan.io/dns/domain/{entity.value}"
        observations: list[Observation] = []
        for page in range(1, MAX_PAGES + 1):
            params = {"key": key, **({"page": str(page)} if page > 1 else {})}
            resp = await ctx.http.get(base, params=params)
            if resp.status_code != 200:
                raise failure("shodan", resp.status_code)
            try:
                data = resp.json()
                labels = data.get("subdomains", [])
                rows = data.get("data", [])
            except (ValueError, AttributeError) as exc:
                raise ModuleError("shodan returned an unexpected payload") from exc
            if not isinstance(labels, list) or not isinstance(rows, list):
                raise ModuleError("shodan returned an unexpected payload")
            by_name: dict[str, list[dict]] = {}
            for label in labels:
                if isinstance(label, str) and label.strip("."):
                    by_name.setdefault(f"{label.strip('.')}.{entity.value}", [])
            for row in rows:
                if isinstance(row, dict) and isinstance(row.get("subdomain"), str) and row["subdomain"].strip("."):
                    name = f"{row['subdomain'].strip('.')}.{entity.value}"
                    by_name.setdefault(name, []).append({k: row[k] for k in _KEPT if k in row})
            request = f"GET {base}" + (f"?page={page}" if page > 1 else "")  # never the key
            payloads = {n: json.dumps(r, sort_keys=True) for n, r in by_name.items()}
            observations += name_observations("shodan", request, entity.value, payloads)
            if not data.get("more"):
                break
        return observations
