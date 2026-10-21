import ipaddress

from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules._lanes import once_per_network
from scrutator.modules.base import Module, ModuleContext, ModuleError, Observation, http_failure
from scrutator.modules.registry import register


def _covering(data: dict) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """The announced prefix an answer is about, when it says that no more specific prefix is announced inside it: only
    then does the answer hold for every address in the prefix."""
    try:
        prefix = ipaddress.ip_network(str(data["resource"]), strict=False)
    except (KeyError, TypeError, ValueError):
        return None
    if prefix.num_addresses == 1 or not data.get("announced"):
        return None
    if data.get("related_prefixes") or data.get("actual_num_related", 1) != 0:
        return None  # more specifics are announced inside it, possibly by someone else
    return prefix


@register
class Asn(Module):
    """Which autonomous system announces an IP, via RIPEstat prefix-overview (no key).

    The answer names the announced prefix that covers the address and says whether more specific prefixes are
    announced inside it. When none are, the answer holds for every address in the prefix: another address of the scan
    inside it is not asked again, and its `announced_by` relation cites that record, whose prefix anyone can check
    (a CDN puts dozens of a site's addresses in a few prefixes)."""

    name = "asn"
    accepts = frozenset({EntityType.IP})
    priority = 20
    concurrency = 8  # RIPEstat allows 8 at a time per client, shared with the ripestat module
    rate_group = "ripestat"
    source = "ripestat"  # the same service as the ripestat module: one name in --sources covers both
    noncommercial = True  # the README's source terms: free for non-commercial (or evaluation) use only
    licence_note = (
        "RIPEstat's terms allow non-commercial use only, forbid redistributing its data without permission and "
        "ask you to credit RIPE NCC and the original source. Bundles that embed RIPEstat responses inherit this."
    )

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation]:
        address = ipaddress.ip_address(entity.value)
        prefixes: list = ctx.cache.setdefault("asn-prefixes", [])

        def covered():
            for prefix, answer in prefixes:
                if prefix.version == address.version and address in prefix:
                    return list(answer)
            return None

        return await once_per_network(ctx.cache, "asn", address, covered, lambda: self._ask(entity, address, ctx), lambda: len(prefixes))

    async def _ask(self, entity: Entity, address, ctx: ModuleContext) -> list[Observation]:
        resp = await ctx.http.get(
            "https://stat.ripe.net/data/prefix-overview/data.json",
            params={"resource": entity.value, "sourceapp": "scrutator"},
        )
        if resp.status_code != 200:
            raise http_failure("ripestat", resp.status_code)
        try:
            data = resp.json()["data"]
            asns = data["asns"]
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
        prefix = _covering(data) if isinstance(data, dict) else None
        if prefix is not None and address in prefix and observations:
            ctx.cache.setdefault("asn-prefixes", []).append((prefix, tuple(observations)))
        return observations
