import json

from scrutator.model import Entity, EntityType
from scrutator.modules._names import name_observations
from scrutator.modules.base import Module, ModuleContext, ModuleError, Observation
from scrutator.modules.keyed._common import api_key, failure
from scrutator.modules.registry import register


@register
class SecurityTrails(Module):
    """Subdomains SecurityTrails holds for a domain: `GET /v1/domain/{domain}/subdomains` with the key in the
    `APIKEY` header. The answer lists labels (`www`), which are joined to the domain. Claims until DNS or a
    certificate agrees.

    Implemented against the documented API, not live-verified (no key was available)."""

    name = "securitytrails"
    accepts = frozenset({EntityType.DOMAIN})
    needs_key = "SCRUTATOR_SECURITYTRAILS_KEY"
    concurrency = 1
    timeout = 60.0
    priority = 0
    apex_only = True
    rate_group = "securitytrails"
    licence_note = (
        "SecurityTrails terms depend on the plan your key belongs to (the free plan has a small monthly query "
        "allowance). You hold the key, so you hold the licence."
    )

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation]:
        key = api_key(self)
        url = f"https://api.securitytrails.com/v1/domain/{entity.value}/subdomains"
        resp = await ctx.http.get(url, params={"children_only": "false", "include_inactive": "false"}, headers={"APIKEY": key})
        if resp.status_code != 200:
            raise failure("securitytrails", resp.status_code)
        try:
            labels = resp.json()["subdomains"]
        except (ValueError, KeyError, TypeError) as exc:
            raise ModuleError("securitytrails returned an unexpected payload") from exc
        if not isinstance(labels, list):
            raise ModuleError("securitytrails returned an unexpected payload")
        slices = {
            f"{label.strip('.')}.{entity.value}": json.dumps({"subdomain": label})
            for label in labels
            if isinstance(label, str) and label.strip(".")
        }
        return name_observations("securitytrails", f"GET {resp.request.url}", entity.value, slices)
