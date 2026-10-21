"""Opt-in zone transfer (`scan --axfr --active`): ask each of the zone's own name servers once for the whole zone.

A zone transfer (AXFR) is what secondary name servers use to copy a zone. Most servers refuse it to strangers; a few
publish their zone this way on purpose (zonetransfer.me exists to show it). Unlike every passive source it is a direct
question to the target's own name servers, so it never runs unless asked for twice: `--axfr` names the module and
`--active` confirms active-ish querying, which the audit log records before any lookup.

What it asks, and nothing more: the in-scope apex's NS records through the scan's resolver, each name server's first
address, then ONE transfer per name server (TCP 53, `XFR_TIMEOUT` seconds). Every outcome is evidence: the zone (its
records, sorted), or the refusal, timeout or error, so "the server refused" is a recorded fact, not silence. Names in the
zone at or under the apex become names of the scan (owners, and record targets inside the zone).
"""

from __future__ import annotations

import asyncio

import dns.exception
import dns.name
import dns.query
import dns.rdatatype
import dns.xfr
import dns.zone

from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules._names import host_entity, rel_for
from scrutator.modules.base import Fact, Mode, Module, ModuleContext, ModuleError, Observation
from scrutator.modules.registry import register
from scrutator.resolver import lookup_status

XFR_PORT = 53
XFR_TIMEOUT = 10.0
MAX_RECORDS = 50_000
_TARGET_TYPES = {"CNAME", "NS", "MX", "SRV", "PTR", "AFSDB", "RP", "NAPTR", "DNAME"}


def _transfer(address: str, zone: str, port: int, timeout: float) -> dns.zone.Zone:
    """One AXFR, blocking (run in a thread). Raises on refusal, timeout or a broken answer."""
    origin = dns.name.from_text(zone)
    xfr = dns.query.xfr(address, origin, port=port, timeout=timeout, lifetime=timeout * 2, relativize=False)
    return dns.zone.from_xfr(xfr, relativize=False, check_origin=False)


def zone_text(zone: dns.zone.Zone) -> list[str]:
    lines = []
    for name, node in zone.nodes.items():
        for rdataset in node.rdatasets:
            for rdata in rdataset:
                lines.append(f"{name.to_text()} {rdataset.ttl} IN {dns.rdatatype.to_text(rdataset.rdtype)} {rdata.to_text()}")
    return sorted(lines)


def names_in(lines: list[str], apex: str) -> list[str]:
    """Owner names, and the host names records point at, that are at or under the apex."""
    found: set[str] = set()
    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        candidates = [parts[0]]
        rtype = parts[3]
        if rtype in _TARGET_TYPES:
            candidates += [p for p in parts[4:] if p.endswith(".")]
        for raw in candidates:
            name = raw.rstrip(".").lower()
            if name == apex or name.endswith("." + apex):
                found.add(name)
    return sorted(found)


@register
class Axfr(Module):
    name = "axfr"
    name_weight = 3
    accepts = frozenset({EntityType.DOMAIN})
    mode = Mode.ACTIVE
    opt_in = "--axfr (with --active)"
    apex_only = True
    concurrency = 1
    timeout = 120.0
    priority = 1
    breaker = False
    replayable = False  # an active question to the target's own servers is never re-asked by a verifier
    licence_note = (
        "Asks the zone's own name servers for a zone transfer (TCP 53), one attempt each. Active-ish: only with "
        "--axfr and --active, recorded in the audit log; use only on zones you are authorised to test."
    )

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation | Fact]:
        apex = entity.value
        ns_answer = await lookup_status(ctx.resolver, apex, "NS")
        servers = sorted({r.rstrip(".").lower() for r in ns_answer.records}) if ns_answer.status == "answer" else []
        if not servers:
            raise ModuleError(f"no NS records for {apex}: nothing to ask for a transfer")
        out: list[Observation | Fact] = []
        for server in servers:
            address_answer = await lookup_status(ctx.resolver, server, "A")
            addresses = sorted(address_answer.records) if address_answer.status == "answer" else []
            if not addresses:
                out.append(Fact(Evidence.create(self.name, f"AXFR {apex} @{server}", "NO ADDRESS: the name server did not resolve")))
                continue
            address = addresses[0]
            request = f"AXFR {apex} @{server} ({address})"
            try:
                zone = await asyncio.to_thread(_transfer, address, apex, XFR_PORT, XFR_TIMEOUT)
            except dns.xfr.TransferError as exc:
                out.append(Fact(Evidence.create(self.name, request, f"REFUSED: {exc}")))
                continue
            except dns.exception.Timeout:
                out.append(Fact(Evidence.create(self.name, request, f"TIMEOUT: no transfer within {XFR_TIMEOUT:g} s")))
                continue
            except (dns.exception.DNSException, OSError, EOFError, ValueError) as exc:
                out.append(Fact(Evidence.create(self.name, request, f"FAILED: {type(exc).__name__}: {exc}"[:500])))
                continue
            lines = zone_text(zone)[:MAX_RECORDS]
            evidence = Evidence.create(self.name, request, "\n".join(lines))
            observed = False
            for name in names_in(lines, apex):
                target = host_entity(name)
                if target is not None and target.value != apex:
                    out.append(Observation(target, rel_for(apex, target.value), evidence))
                    observed = True
            if not observed:
                out.append(Fact(evidence))
        return out
