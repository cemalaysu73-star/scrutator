import json

from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules.base import Fact, Module, ModuleContext, ModuleError, SourceUnavailable, http_failure
from scrutator.modules.registry import register

SOURCEAPP = "scrutator"  # RIPEstat asks heavy or regular users to identify their application
_WHOIS_KEYS = ("netname", "descr", "country")


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
        except (ValueError, KeyError, TypeError, AttributeError):
            failures.append(ModuleError("ripestat whois returned an unexpected payload"))
        except ModuleError as exc:
            failures.append(exc)

        if failures and not facts and len(failures) == 2:
            raise next((f for f in failures if isinstance(f, SourceUnavailable)), failures[0])
        return facts
