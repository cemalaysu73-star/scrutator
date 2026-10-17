from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules.base import Module, ModuleContext, ModuleError, Observation, http_failure
from scrutator.modules.registry import register


@register
class Asn(Module):
    """Which autonomous system announces an IP, via RIPEstat prefix-overview (no key)."""

    name = "asn"
    accepts = frozenset({EntityType.IP})
    priority = 20
    concurrency = 4  # RIPEstat allows 8 at a time per client, shared with the ripestat module
    rate_group = "ripestat"
    licence_note = (
        "RIPEstat's terms allow non-commercial use only, forbid redistributing its data without permission and "
        "ask you to credit RIPE NCC and the original source. Bundles that embed RIPEstat responses inherit this."
    )

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation]:
        resp = await ctx.http.get(
            "https://stat.ripe.net/data/prefix-overview/data.json",
            params={"resource": entity.value, "sourceapp": "scrutator"},
        )
        if resp.status_code != 200:
            raise http_failure("ripestat", resp.status_code)
        try:
            asns = resp.json()["data"]["asns"]
        except (ValueError, KeyError, TypeError) as exc:
            raise ModuleError("ripestat returned an unexpected payload") from exc

        evidence = Evidence.create(self.name, f"GET {resp.request.url}", resp.text)
        observations: list[Observation] = []
        for item in asns:
            try:
                target = Entity(type=EntityType.ASN, value=str(item["asn"]))
            except (KeyError, TypeError, ValueError):
                continue
            observations.append(Observation(target, "announced_by", evidence))
        return observations
