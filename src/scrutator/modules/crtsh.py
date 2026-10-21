import json

from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules._names import host_entity, rel_for
from scrutator.modules.base import Module, ModuleContext, ModuleError, Observation, http_failure
from scrutator.modules.registry import register

_CERT_FIELDS = ("id", "issuer_name", "name_value", "not_before", "not_after")


@register
class CrtSh(Module):
    """Certificate Transparency names via crt.sh (no key)."""

    name = "crtsh"
    name_weight = 3
    accepts = frozenset({EntityType.DOMAIN})
    concurrency = 1
    timeout = 90.0
    priority = 0
    apex_only = True

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation]:
        resp = await ctx.http.get("https://crt.sh/", params={"q": f"%.{entity.value}", "output": "json"})
        if resp.status_code != 200:
            raise http_failure("crt.sh", resp.status_code)
        try:
            rows = resp.json()
        except ValueError as exc:
            raise ModuleError("crt.sh returned invalid JSON") from exc
        if not isinstance(rows, list):
            raise ModuleError("crt.sh returned an unexpected payload")

        certs_by_name: dict[str, list[dict]] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            summary = {key: row.get(key) for key in _CERT_FIELDS}
            for raw in str(row.get("name_value", "")).splitlines():
                name = raw.strip().lower().removeprefix("*.")
                found = host_entity(name)
                if found is None or found.value == entity.value:
                    continue
                bucket = certs_by_name.setdefault(found.value, [])
                if summary not in bucket:
                    bucket.append(summary)

        request = str(resp.request.url)
        return [
            Observation(
                Entity(type=EntityType.DOMAIN, value=name),
                rel_for(entity.value, name),
                Evidence.create(self.name, f"GET {request}", json.dumps(certs, sort_keys=True)),
            )
            for name, certs in sorted(certs_by_name.items())
        ]
