from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules._names import host_entity
from scrutator.modules.base import Module, ModuleContext, ModuleError, Observation
from scrutator.modules.registry import register


def _vcard_name(entity: dict) -> str | None:
    card = entity.get("vcardArray")
    if not (isinstance(card, list) and len(card) == 2 and isinstance(card[1], list)):
        return None
    for item in card[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
            return str(item[3])
    return None


def _org(value: str | None) -> Entity | None:
    if not value:
        return None
    try:
        return Entity(type=EntityType.ORG, value=value)
    except ValueError:
        return None


@register
class Rdap(Module):
    """Registration data for a domain (name servers, registrar) or an IP (network owner)
    through the rdap.org bootstrap redirector."""

    name = "rdap"
    accepts = frozenset({EntityType.DOMAIN, EntityType.IP})

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation]:
        kind = "ip" if entity.type is EntityType.IP else "domain"
        resp = await ctx.http.get(f"https://rdap.org/{kind}/{entity.value}")
        if resp.status_code == 404:
            return []
        if resp.status_code != 200:
            raise ModuleError(f"rdap returned HTTP {resp.status_code}")
        try:
            data = resp.json()
        except ValueError as exc:
            raise ModuleError("rdap returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise ModuleError("rdap returned an unexpected payload")

        evidence = Evidence.create(self.name, f"GET {resp.request.url}", resp.text)
        observations: list[Observation] = []
        if entity.type is EntityType.IP:
            owner = _org(data.get("name"))
            if owner:
                observations.append(Observation(owner, "netblock_owner", evidence))
            return observations

        for ns in data.get("nameservers", []):
            target = host_entity(str(ns.get("ldhName", ""))) if isinstance(ns, dict) else None
            if target:
                observations.append(Observation(target, "ns", evidence))
        for sub in data.get("entities", []):
            if isinstance(sub, dict) and "registrar" in sub.get("roles", []):
                registrar = _org(_vcard_name(sub))
                if registrar:
                    observations.append(Observation(registrar, "registrar", evidence))
        return observations
