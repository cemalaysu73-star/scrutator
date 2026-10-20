import secrets

from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules.base import Fact, Module, ModuleContext
from scrutator.modules.registry import register
from scrutator.resolver import lookup_status

PROBE_PREFIX = "wc-probe-"


@register
class Wildcard(Module):
    """Does this zone answer for names that cannot exist? One random label under the apex is looked
    up for A and AAAA, and the answer, or the NXDOMAIN, is recorded like any other DNS lookup.

    A zone with a wildcard record resolves every name, so a name that resolves only to what the random
    label also resolves to is not proof that the name exists (see `scrutator.names`). The probe name
    is a child of the apex, which the engine only runs this on when it is in scope; nothing outside the
    scope is asked. Wildcards below a delegated sub-zone are not probed."""

    name = "wildcard"
    accepts = frozenset({EntityType.DOMAIN})
    concurrency = 4
    priority = 5
    apex_only = True
    source = "dns"  # the probe is a DNS lookup: allowing dns allows it

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Fact]:
        probe = f"{PROBE_PREFIX}{secrets.token_hex(6)}.{entity.value}"
        if len(probe) > 253:
            return []
        facts: list[Fact] = []
        for rtype in ("A", "AAAA"):
            answer = None
            for _attempt in range(2):  # a busy resolver drops a query now and then: ask again before giving up
                try:
                    answer = await lookup_status(ctx.resolver, probe, rtype)
                    break
                except Exception:  # noqa: BLE001 - the probe is an extra: silence, never a finding
                    continue
            if answer is None:
                continue
            if answer.status == "answer" or answer.negative:
                facts.append(Fact(Evidence.create("dns", f"DNS {rtype} {probe}", answer.payload())))
        return facts
