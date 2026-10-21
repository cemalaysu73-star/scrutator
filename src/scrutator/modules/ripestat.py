import ipaddress
import json

from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules.base import Fact, Module, ModuleContext, ModuleError, SourceUnavailable, http_failure
from scrutator.modules._lanes import once_per_network
from scrutator.modules.registry import register

SOURCEAPP = "scrutator"  # RIPEstat asks heavy or regular users to identify their application
# The network's range is kept too (R6): it is what lets another address of the scan inside the same network rest on
# this record instead of asking again, and what lets anyone reading the bundle check that it does.
_RANGE_KEYS = ("inetnum", "inet6num", "NetRange", "CIDR")
_WHOIS_KEYS = ("netname", "descr", "country", *_RANGE_KEYS)


def parse_range(value: object) -> tuple | None:
    """(first, last) of a whois range: `a - b` or one CIDR prefix (ARIN's comma-separated CIDR lists are refused)."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    try:
        if " - " in text:
            first, last = (ipaddress.ip_address(part.strip()) for part in text.split(" - ", 1))
        elif "," not in text:
            network = ipaddress.ip_network(text, strict=False)
            first, last = network[0], network[-1]
        else:
            return None
    except ValueError:
        return None
    return (first, last) if first.version == last.version and first <= last else None


def network_of(rows: list[dict], address) -> tuple | None:
    """The most specific range in a whois answer's rows that contains `address`."""
    best = None
    for row in rows:
        if isinstance(row, dict) and row.get("key") in _RANGE_KEYS:
            found = parse_range(row.get("value"))
            if found and found[0].version == address.version and found[0] <= address <= found[1]:
                if best is None or int(found[1]) - int(found[0]) < int(best[1]) - int(best[0]):
                    best = found
    return best


@register
class RipeStat(Module):
    """Who looks after an address, from RIPEstat (no key): the abuse contact and the network's name,
    description and country (`abuse-contact-finder` and `whois`). Both are facts about the address;
    no new entity is created, because an abuse mailbox is an ownership hint, not something to scan.

    A failing call does not discard the other: the module fails only when both do."""

    name = "ripestat"
    accepts = frozenset({EntityType.IP})
    concurrency = 8  # RIPEstat allows 8 at once per client; shared with the asn module
    timeout = 45.0
    priority = 28
    rate_group = "ripestat"
    noncommercial = True  # the README's source terms: free for non-commercial (or evaluation) use only
    licence_note = (
        "RIPEstat's terms allow non-commercial use only, forbid redistributing its data without permission and "
        "ask you to credit RIPE NCC and the original source. Bundles that embed RIPEstat responses inherit this."
    )

    async def _get(self, ctx: ModuleContext, call: str, entity: Entity):
        return await ctx.http.get(
            f"https://stat.ripe.net/data/{call}/data.json",
            params={"resource": entity.value, "sourceapp": SOURCEAPP},
        )

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Fact]:
        """An address inside a network whose whois record this scan already holds is not asked again: the abuse contact
        and the network's name belong to the network, and `scrutator.exposure` gives the address the facts of the
        record whose range contains it (saying which address was asked)."""
        address = ipaddress.ip_address(entity.value)
        networks: list = ctx.cache.setdefault("ripestat-networks", [])

        def covered():
            for first, last in networks:
                if first.version == address.version and first <= address <= last:
                    return []
            return None

        return await once_per_network(ctx.cache, "ripestat", address, covered, lambda: self._ask(entity, address, ctx), lambda: len(networks))

    async def _ask(self, entity: Entity, address, ctx: ModuleContext) -> list[Fact]:
        facts: list[Fact] = []
        failures: list[Exception] = []

        resp = await self._get(ctx, "abuse-contact-finder", entity)
        try:
            if resp.status_code != 200:
                raise http_failure("ripestat", resp.status_code)
            contacts = resp.json()["data"]["abuse_contacts"]
            if isinstance(contacts, list) and contacts:
                payload = json.dumps([{"abuse_contacts": sorted(str(c) for c in contacts)}])
                facts.append(Fact(Evidence.create(self.name, f"GET {resp.request.url}", payload)))
        except (ValueError, KeyError, TypeError) as exc:
            failures.append(ModuleError("ripestat abuse-contact-finder returned an unexpected payload"))
        except ModuleError as exc:
            failures.append(exc)

        resp = await self._get(ctx, "whois", entity)
        try:
            if resp.status_code != 200:
                raise http_failure("ripestat", resp.status_code)
            records = resp.json()["data"]["records"]
            rows, seen = [], set()
            for block in records:
                for item in block:
                    key = item.get("key")
                    if key in _WHOIS_KEYS and (key, item.get("value")) not in seen:
                        seen.add((key, item.get("value")))
                        rows.append({"key": key, "value": item.get("value")})
            if rows:
                facts.append(Fact(Evidence.create(self.name, f"GET {resp.request.url}", json.dumps(rows, sort_keys=True))))
                known = network_of(rows, address)
                if known is not None and any(isinstance(f, Fact) and "abuse-contact-finder" in f.evidence.request for f in facts):
                    # only a network whose abuse contact was also read covers other addresses: both are inherited
                    ctx.cache.setdefault("ripestat-networks", []).append(known)
        except (ValueError, KeyError, TypeError, AttributeError):
            failures.append(ModuleError("ripestat whois returned an unexpected payload"))
        except ModuleError as exc:
            failures.append(exc)

        if failures and not facts and len(failures) == 2:
            raise next((f for f in failures if isinstance(f, SourceUnavailable)), failures[0])
        return facts
