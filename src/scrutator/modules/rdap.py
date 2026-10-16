from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules._names import host_entity
from scrutator.modules.base import Fact, Module, ModuleContext, ModuleError, Observation
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

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation | Fact]:
        kind = "ip" if entity.type is EntityType.IP else "domain"
        url = f"https://rdap.org/{kind}/{entity.value}"
        resp = await ctx.http.get(url)
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

        # Record the request that was made, not the registry the redirector sent us to:
        # replay repeats this request and follows the same redirect.
        evidence = Evidence.create(self.name, f"GET {url}", resp.text)
        observations: list[Observation | Fact] = []
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
        if not observations:
            # no name server or registrar to hang a relation on: the registration dates (expiry)
            # are still evidence the scan holds
            observations.append(Fact(evidence))
        return observations
