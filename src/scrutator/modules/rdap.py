import asyncio
import ipaddress

from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules._names import host_entity, usable_org
from scrutator.modules.base import Fact, Module, ModuleContext, ModuleError, Observation, http_failure
from scrutator.modules.registry import register


def _vcard_value(entity: dict, properties: tuple[str, ...] = ("fn",)) -> str | None:
    card = entity.get("vcardArray")
    if not (isinstance(card, list) and len(card) == 2 and isinstance(card[1], list)):
        return None
    for wanted in properties:
        for item in card[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == wanted:
                return str(item[3])
    return None


def _org(value: str | None) -> Entity | None:
    if not value:
        return None
    try:
        return Entity(type=EntityType.ORG, value=value)
    except ValueError:
        return None


def _range(data: dict) -> tuple | None:
    """(first, last) address of the network an RDAP answer describes, or None."""
    try:
        first = ipaddress.ip_address(str(data["startAddress"]))
        last = ipaddress.ip_address(str(data["endAddress"]))
    except (KeyError, ValueError):
        return None
    return (first, last) if first.version == last.version and first <= last else None


@register
class Rdap(Module):
    """Registration data for a domain (name servers, registrar, and the registrant when the
    registry publishes one) or an IP (network owner) through the rdap.org bootstrap redirector.

    An RDAP answer about an address describes its whole network (first and last address, handle, owner),
    and a site on a CDN has dozens of addresses in a handful of networks: 50 addresses of owasp.org are in
    20. So an address inside a network already looked up in this scan is not asked again; its
    `netblock_owner` relation cites the record that contains it, whose range anyone can check."""

    name = "rdap"
    accepts = frozenset({EntityType.DOMAIN, EntityType.IP})
    priority = 30
    concurrency = 4  # at 8 at once rdap.org answered 429 to a third of the requests and the back-off cost more than it saved
    apex_only = True  # registration data is per registered domain; a subdomain gets HTTP 400

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation | Fact]:
        if entity.type is not EntityType.IP:
            return await self._ask(entity, ctx)
        # Addresses next to each other are mostly in one network. Looking them up one after the other
        # (within a /16, or a /32 for IPv6) lets the first answer cover the rest, where all at once would
        # ask the same network again and again; addresses far apart still go in parallel.
        address = ipaddress.ip_address(entity.value)
        lane = (address.version, int(address) >> (16 if address.version == 4 else 96))
        async with ctx.cache.setdefault("rdap-lanes", {}).setdefault(lane, asyncio.Lock()):
            for first, last, record, owner in ctx.cache.setdefault("rdap-networks", []):
                if first.version == address.version and first <= address <= last:
                    return [Observation(owner, "netblock_owner", record)] if owner else []
            return await self._ask(entity, ctx)

    async def _ask(self, entity: Entity, ctx: ModuleContext) -> list[Observation | Fact]:
        kind = "ip" if entity.type is EntityType.IP else "domain"
        networks: list = ctx.cache.setdefault("rdap-networks", [])
        url = f"https://rdap.org/{kind}/{entity.value}"
        resp = await ctx.http.get(url)
        if resp.status_code == 404:
            return []
        if resp.status_code != 200:
            raise http_failure("rdap", resp.status_code)
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
            known = _range(data)
            if known:
                networks.append((*known, evidence, owner))
            return observations

        for ns in data.get("nameservers", []):
            target = host_entity(str(ns.get("ldhName", ""))) if isinstance(ns, dict) else None
            if target:
                observations.append(Observation(target, "ns", evidence))
        for sub in data.get("entities", []):
            if not isinstance(sub, dict):
                continue
            roles = sub.get("roles", [])
            if "registrar" in roles:
                registrar = _org(_vcard_value(sub))
                if registrar:
                    observations.append(Observation(registrar, "registrar", evidence))
            if "registrant" in roles:
                registrant = _org(usable_org(_vcard_value(sub, ("fn", "org"))))
                if registrant:
                    observations.append(Observation(registrant, "registrant", evidence))
        if not observations:
            # no name server or registrar to hang a relation on: the registration dates (expiry)
            # are still evidence the scan holds
            observations.append(Fact(evidence))
        return observations
