"""Scans built by hand for the active-confirmation tests: in-scope names that resolve to addresses, with the passive
evidence (InternetDB ports, an announcing AS, a CNAME) the plan reads. Addresses are RFC 5737 documentation addresses
(allowed only through the tests' `relax`) or 127.0.0.1 (a local listener standing in for a server)."""

import json
from contextlib import asynccontextmanager

from scrutator.active.guard import Limits
from scrutator.active.run import ActiveConfig
from scrutator.model import Entity, EntityType, Evidence, ScopeState
from scrutator.store import Store

RELAX = frozenset({"loopback", "documentation"})
FAST = Limits(connect_timeout=0.5, banner_timeout=0.3, handshake_timeout=1.5, http_timeout=1.5, rate_per_second=50.0, deadline_s=30.0)


def config(**changes) -> ActiveConfig:
    limits = Limits(**{**FAST.__dict__, **changes}) if changes else FAST
    return ActiveConfig(limits=limits, relax=RELAX)


def make_active_store(names: dict[str, list[str]], *, ports=None, asns=None, cnames=None, netnames=None, hostnames=None,
                      authorisation=True, path=":memory:", domain="example.com"):
    """`names`: in-scope name -> the addresses it resolves to. `ports`: address -> ports InternetDB lists. `asns`:
    address -> AS number. `cnames`: name -> CNAME target. `netnames`: address -> RIPEstat network name."""
    store = Store(path)
    sid = store.create_scan(domain)
    store.set_meta(sid, "scope", json.dumps({"domains": [domain], "cidrs": [], "asns": []}))
    root = Entity(type=EntityType.DOMAIN, value=domain)
    store.upsert_entity(sid, root, ScopeState.IN)
    seen_ips: set[str] = set()
    for name, ips in names.items():
        entity = Entity(type=EntityType.DOMAIN, value=name)
        store.upsert_entity(sid, entity, ScopeState.IN)
        for ip in ips:
            ip_entity = Entity(type=EntityType.IP, value=ip)
            store.upsert_entity(sid, ip_entity, ScopeState.LINKED)
            evidence = Evidence.create("dns", f"DNS A {name}", "\n".join(sorted(ips)))
            store.add_evidence(evidence)
            store.add_edge(sid, entity.id, "resolves_to", ip_entity.id, [evidence.id])
            seen_ips.add(ip)
    for name, target in (cnames or {}).items():
        evidence = Evidence.create("dns", f"DNS CNAME {name}", target + ".")
        store.add_evidence(evidence)
        store.add_scan_evidence(sid, evidence.id)
    for ip in sorted(seen_ips):
        listed = (ports or {}).get(ip)
        if listed is not None or (hostnames or {}).get(ip):
            row = {"ip": ip, "ports": sorted(listed)} if listed is not None else None
            if row:
                evidence = Evidence.create("internetdb", f"GET https://internetdb.shodan.io/{ip}", json.dumps([row], sort_keys=True))
                store.add_evidence(evidence)
                store.add_scan_evidence(sid, evidence.id)
            if (hostnames or {}).get(ip):
                evidence = Evidence.create("internetdb", f"GET https://internetdb.shodan.io/{ip}", json.dumps([{"ip": ip, "hostnames": hostnames[ip]}], sort_keys=True))
                store.add_evidence(evidence)
                store.add_scan_evidence(sid, evidence.id)
        if (asns or {}).get(ip):
            asn = Entity(type=EntityType.ASN, value=str(asns[ip]))
            store.upsert_entity(sid, asn, ScopeState.LINKED)
            evidence = Evidence.create("asn", f"ASN of {ip}", str(asns[ip]))
            store.add_evidence(evidence)
            store.add_edge(sid, Entity(type=EntityType.IP, value=ip).id, "announced_by", asn.id, [evidence.id])
        if (netnames or {}).get(ip):
            evidence = Evidence.create(
                "ripestat", f"GET https://stat.ripe.net/data/whois/data.json?resource={ip}",
                json.dumps([{"key": "netname", "value": netnames[ip]}], sort_keys=True),
            )
            store.add_evidence(evidence)
            store.add_scan_evidence(sid, evidence.id)
    if authorisation:
        store.append_audit(sid, {"event": "self_attestation", "domains": [domain], "organisation": "", "confirmed": "--yes", "active": True})
    return store, sid


def self_authorisation(domain="example.com", *, active=True):
    from scrutator.audit.content import self_event

    return [self_event([domain], "", "--yes", active=active)]
