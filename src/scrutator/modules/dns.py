import asyncio
import re

from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules._names import host_entity
from scrutator.modules.base import Fact, Module, ModuleContext, Observation
from scrutator.modules.registry import register
from scrutator.resolver import DnsAnswer, lookup_status

_SPF_REF = re.compile(r"(?:include:|redirect=)([^\s\"]+)")
_MAX_NAME = 240  # leaves room for the "_dmarc." prefix inside the 253-character limit


def _names(rtype: str, answer: str) -> list[str]:
    if rtype == "MX":
        parts = answer.split()
        return parts[-1:]
    if rtype == "TXT":
        return _SPF_REF.findall(answer)
    return [answer]


@register
class Dns(Module):
    """A, AAAA, CNAME, MX, NS and SPF references for a hostname, plus the evidence of absence
    and the mail-authentication records the risk rules need.

    Every name queried here is the entity itself or `_dmarc.<entity>`. The engine only runs
    this module on in-scope entities, and a name under an in-scope domain is in scope, so no
    query leaves the scope."""

    name = "dns"
    accepts = frozenset({EntityType.DOMAIN})
    concurrency = 8
    priority = 10
    breaker = False  # the resolver is the scan's own, not a remote service to give up on

    _QUERIES = (
        ("A", "resolves_to"),
        ("AAAA", "resolves_to"),
        ("CNAME", "cname_to"),
        ("MX", "mx"),
        ("NS", "ns"),
        ("TXT", "spf_include"),
    )

    @staticmethod
    def _evidence(name: str, rtype: str, answer: DnsAnswer) -> Evidence:
        return Evidence.create("dns", f"DNS {rtype} {name}", answer.payload())

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation | Fact]:
        seen: set[tuple[str, str]] = set()
        observations: list[Observation] = []
        facts: list[Fact] = []
        attached: set[str] = set()  # evidence already cited by an observation
        # the queries do not depend on each other: ask them together, then read the answers in the
        # fixed order so the evidence and the relations come out the same every time
        results = await asyncio.gather(
            *(self._ask(ctx, entity.value, rtype) for rtype, _ in self._QUERIES), return_exceptions=True
        )
        failed = [r for r in results if isinstance(r, Exception)]
        if len(failed) == len(results):
            raise failed[0]  # nothing answered: the run failed, it did not find an empty name
        for (rtype, rel), answer in zip(self._QUERIES, results):
            if isinstance(answer, Exception):
                continue  # one lookup that timed out leaves the others' answers intact; silence is no evidence
            if answer.status != "answer":
                if rtype == "A" and answer.status == "nxdomain":
                    facts.append(Fact(self._evidence(entity.value, rtype, answer)))
                continue
            evidence = self._evidence(entity.value, rtype, answer)
            spf_seen = False
            for record in answer.records:
                if rtype == "TXT":
                    if "v=spf1" not in record:
                        continue
                    spf_seen = True
                for raw in _names(rtype, record):
                    target = self._entity_for(rtype, raw)
                    if target is None or target == entity or (rel, target.id) in seen:
                        continue
                    seen.add((rel, target.id))
                    observations.append(Observation(target, rel, evidence))
                    attached.add(evidence.id)
            if spf_seen and evidence.id not in attached:
                facts.append(Fact(evidence))  # an SPF record with no include or redirect

        sends_mail = any(o.rel == "mx" for o in observations)
        is_zone = any(o.rel == "ns" for o in observations)
        if (sends_mail or is_zone) and len(entity.value) <= _MAX_NAME:
            facts.extend(await self._auxiliary(ctx, f"_dmarc.{entity.value}", "TXT"))
        if is_zone:
            facts.extend(await self._auxiliary(ctx, entity.value, "CAA"))
        return [*observations, *facts]

    @staticmethod
    async def _ask(ctx: ModuleContext, name: str, rtype: str) -> DnsAnswer:
        """One lookup, tried twice: a shared resolver that drops a query under load usually answers the next."""
        try:
            return await lookup_status(ctx.resolver, name, rtype)
        except Exception:  # noqa: BLE001
            return await lookup_status(ctx.resolver, name, rtype)

    async def _auxiliary(self, ctx: ModuleContext, name: str, rtype: str) -> list[Fact]:
        """A positive or definite-negative answer as a fact. These lookups are extras: a
        failure here must not discard what the main queries found."""
        try:
            answer = await lookup_status(ctx.resolver, name, rtype)
        except Exception:  # noqa: BLE001
            return []
        if answer.status == "answer" or answer.negative:
            return [Fact(self._evidence(name, rtype, answer))]
        return []

    @staticmethod
    def _entity_for(rtype: str, raw: str) -> Entity | None:
        if rtype in ("A", "AAAA"):
            try:
                return Entity(type=EntityType.IP, value=raw)
            except ValueError:
                return None
        return host_entity(raw)
