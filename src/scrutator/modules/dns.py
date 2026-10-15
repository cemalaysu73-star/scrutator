import re

from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules._names import host_entity
from scrutator.modules.base import Module, ModuleContext, Observation
from scrutator.modules.registry import register

_SPF_REF = re.compile(r"(?:include:|redirect=)([^\s\"]+)")


def _names(rtype: str, answer: str) -> list[str]:
    if rtype == "MX":
        parts = answer.split()
        return parts[-1:]
    if rtype == "TXT":
        return _SPF_REF.findall(answer)
    return [answer]


@register
class Dns(Module):
    """A, AAAA, CNAME, MX, NS and SPF references for a hostname."""

    name = "dns"
    accepts = frozenset({EntityType.DOMAIN})
    concurrency = 8

    _QUERIES = (
        ("A", "resolves_to"),
        ("AAAA", "resolves_to"),
        ("CNAME", "cname_to"),
        ("MX", "mx"),
        ("NS", "ns"),
        ("TXT", "spf_include"),
    )

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation]:
        seen: set[tuple[str, str]] = set()
        observations: list[Observation] = []
        for rtype, rel in self._QUERIES:
            answers = await ctx.resolver.lookup(entity.value, rtype)
            if not answers:
                continue
            evidence = Evidence.create(self.name, f"DNS {rtype} {entity.value}", "\n".join(answers))
            for answer in answers:
                if rtype == "TXT" and "v=spf1" not in answer:
                    continue
                for raw in _names(rtype, answer):
                    target = self._entity_for(rtype, raw)
                    if target is None or target == entity or (rel, target.id) in seen:
                        continue
                    seen.add((rel, target.id))
                    observations.append(Observation(target, rel, evidence))
        return observations

    @staticmethod
    def _entity_for(rtype: str, raw: str) -> Entity | None:
        if rtype in ("A", "AAAA"):
            try:
                return Entity(type=EntityType.IP, value=raw)
            except ValueError:
                return None
        return host_entity(raw)
