"""Active-probe evidence in a report, parsed once for the risk rules, the report section and `verify`.

A pure reader: it looks only at evidence of the sources `tcp`, `tls`, `http` and `active`, and only at records whose request has
exactly the shape a probe writes, about an address or a name that is an entity of the report in a state the scan was allowed to
look at. A hostile bundle that carries a record about anything else has it ignored here (and `verify` fails it elsewhere).
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field

_IP = r"(\d{1,3}(?:\.\d{1,3}){3})"
_TCP = re.compile(rf"TCP CONNECT {_IP}:(\d{{1,5}})")
_TLS = re.compile(rf"TLS HANDSHAKE {_IP}:(\d{{1,5}}) sni=(\S+)")
_LEGACY = re.compile(rf"TLS LEGACY {_IP}:(\d{{1,5}}) (TLSv1|TLSv1\.1)")
_HTTP = re.compile(rf"HTTP GET (https?)://([a-z0-9.-]+)/ via {_IP}:(\d{{1,5}})")
_PLAN = re.compile(r"ACTIVE PLAN \S+")


@dataclass(frozen=True)
class Rec:
    evidence_id: str
    collected_at: str
    payload: dict


@dataclass
class Records:
    tcp: dict[tuple[str, int], Rec] = field(default_factory=dict)
    tls: dict[tuple[str, int, str], Rec] = field(default_factory=dict)
    legacy: dict[tuple[str, int, str], Rec] = field(default_factory=dict)
    http: dict[tuple[str, int, str, str], Rec] = field(default_factory=dict)
    plan: list[Rec] = field(default_factory=list)

    @property
    def any(self) -> bool:
        return bool(self.tcp or self.tls or self.legacy or self.http or self.plan)


def _port(text: str) -> int | None:
    value = int(text)
    return value if 1 <= value <= 65535 else None


def _keep(table: dict, key, rec: Rec) -> None:
    """One record per key; if a bundle holds two, the later (then the larger id) wins, the same everywhere."""
    old = table.get(key)
    if old is None or (rec.collected_at, rec.evidence_id) > (old.collected_at, old.evidence_id):
        table[key] = rec


def active_records(report: dict) -> Records:
    allowed_ips = {e["value"] for e in report.get("entities", []) if e.get("type") == "ip" and e.get("state") in ("in", "linked")}
    names = {e["value"] for e in report.get("entities", []) if e.get("type") == "domain" and e.get("state") == "in"}
    found = Records()
    for evidence_id in sorted(report.get("evidence", {})):
        record = report["evidence"][evidence_id]
        source, request = record.get("source"), record.get("request", "")
        if source not in ("tcp", "tls", "http", "active"):
            continue
        try:
            payload = json.loads(record["payload"])
        except (ValueError, KeyError, TypeError):
            continue
        if not isinstance(payload, dict):
            continue
        rec = Rec(evidence_id, str(record.get("collected_at", "")), payload)
        if source == "active":
            if _PLAN.fullmatch(request):
                found.plan.append(rec)
            continue
        if source == "tcp" and (m := _TCP.fullmatch(request)):
            ip, port = m.group(1), _port(m.group(2))
            if ip in allowed_ips and port:
                _keep(found.tcp, (ip, port), rec)
        elif source == "tls" and (m := _TLS.fullmatch(request)):
            ip, port, sni = m.group(1), _port(m.group(2)), m.group(3)
            if ip in allowed_ips and port and (sni in names or sni == "-"):
                _keep(found.tls, (ip, port, "" if sni == "-" else sni), rec)
        elif source == "tls" and (m := _LEGACY.fullmatch(request)):
            ip, port = m.group(1), _port(m.group(2))
            if ip in allowed_ips and port:
                _keep(found.legacy, (ip, port, m.group(3)), rec)
        elif source == "http" and (m := _HTTP.fullmatch(request)):
            scheme, name, ip, port = m.group(1), m.group(2), m.group(3), _port(m.group(4))
            if ip in allowed_ips and port and name in names:
                _keep(found.http, (ip, port, name, scheme), rec)
    found.plan.sort(key=lambda r: (r.collected_at, r.evidence_id))
    return found


def valid_ip(text: str) -> bool:
    try:
        return ipaddress.ip_address(text).version == 4
    except ValueError:
        return False
