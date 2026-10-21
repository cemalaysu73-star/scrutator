import ipaddress
import json
from functools import lru_cache
from importlib import resources

from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules._lanes import once_per_network
from scrutator.modules._names import host_entity, usable_org
from scrutator.modules.base import Fact, Module, ModuleContext, ModuleError, Observation, http_failure
from scrutator.modules.registry import register
from scrutator.pacing import Pacer


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


PACE = (8, 1.0)  # (burst, per second) towards rdap.org; tests lift it
RIR_PACE = (10, 5.0)  # towards each regional registry's own RDAP server: they publish no limit; be polite anyway
# The five regional registries' RDAP services, as IANA's bootstrap names them: the only servers asked directly.
RIR_SERVERS = (
    "https://rdap.arin.net/registry/",
    "https://rdap.db.ripe.net/",
    "https://rdap.apnic.net/",
    "https://rdap.lacnic.net/rdap/",
    "https://rdap.afrinic.net/rdap/",
)
RIR_HOSTS = frozenset(url.split("/")[2] for url in RIR_SERVERS)
REUSE_DAYS = 7  # how old a network's registration record in this database may be and still be cited by a new scan


@lru_cache(maxsize=1)
def _bootstrap() -> dict[int, list[tuple]]:
    """IANA's RDAP bootstrap for IP space (RFC 9224), as bundled: version -> [(network, base URL)], most specific
    first. See tools/rdap_bootstrap.py; the RIRs refer a query about space they do not hold on to the one that does."""
    raw = json.loads(resources.files("scrutator.modules").joinpath("rdap_bootstrap.json").read_text(encoding="utf-8"))
    tables: dict[int, list[tuple]] = {4: [], 6: []}
    for family, version in (("ipv4", 4), ("ipv6", 6)):
        for base, prefixes in raw["services"].get(family, {}).items():
            if base not in RIR_SERVERS:
                continue
            for prefix in prefixes:
                try:
                    tables[version].append((ipaddress.ip_network(prefix), base))
                except ValueError:
                    continue
        tables[version].sort(key=lambda item: -item[0].prefixlen)
    return tables


def rir_url(address: str) -> str | None:
    """The URL of the registry that holds a public address, or None: an address that is not globally routable (a
    documentation or private range) is in no registry's data, and an unknown block is left to rdap.org."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return None
    if not ip.is_global:
        return None
    for network, base in _bootstrap()[ip.version]:
        if ip in network:
            return f"{base}ip/{ip}"
    return None


def network_entry(evidence: Evidence) -> tuple | None:
    """(first, last, evidence, owner) for an RDAP answer about an address's network, or None."""
    try:
        data = json.loads(evidence.payload)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    known = _range(data)
    return (*known, evidence, _org(data.get("name"))) if known else None


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
    `netblock_owner` relation cites the record that contains it, whose range anyone can check. A scan also starts
    with the network records an earlier scan in the same database fetched in the last `REUSE_DAYS` days (offered by
    `run_scan` in `ctx.cache["rdap-networks"]`): the record is content-addressed and keeps its own collection time.

    A public address is asked of the regional registry that holds it (IANA's bootstrap, bundled), not through
    rdap.org: the redirector allows about ten requests in ten seconds and was the longest wait of a scan. Domains, and
    addresses the bootstrap does not place, still go through rdap.org."""

    name = "rdap"
    accepts = frozenset({EntityType.DOMAIN, EntityType.IP})
    priority = 30
    concurrency = 4  # at 8 at once rdap.org answered 429 to a third of the requests and the back-off cost more than it saved
    apex_only = True  # registration data is per registered domain; a subdomain gets HTTP 400

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation | Fact]:
        if entity.type is not EntityType.IP:
            return await self._ask(entity, ctx)
        address = ipaddress.ip_address(entity.value)
        networks: list = ctx.cache.setdefault("rdap-networks", [])

        def covered():
            for first, last, record, owner in networks:
                if first.version == address.version and first <= address <= last:
                    return [Observation(owner, "netblock_owner", record)] if owner else []
            return None

        return await once_per_network(ctx.cache, "rdap", address, covered, lambda: self._ask(entity, ctx), lambda: len(networks))

    async def _ask(self, entity: Entity, ctx: ModuleContext) -> list[Observation | Fact]:
        kind = "ip" if entity.type is EntityType.IP else "domain"
        networks: list = ctx.cache.setdefault("rdap-networks", [])
        direct = rir_url(entity.value) if entity.type is EntityType.IP else None
        if direct is not None:
            # straight to the registry that holds the address: no redirector and no redirector's rate limit
            url = direct
            await ctx.cache.setdefault(f"rdap-pace:{direct.split('/')[2]}", Pacer(*RIR_PACE)).take()
        else:
            url = f"https://rdap.org/{kind}/{entity.value}"
            # rdap.org refuses a burst of more than about ten requests (HTTP 429, retry after ~10 s): eight at once, then one a second
            await ctx.cache.setdefault("rdap-pace", Pacer(*PACE)).take()
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
