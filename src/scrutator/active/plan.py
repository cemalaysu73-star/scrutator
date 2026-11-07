"""What active confirmation may touch: a pure function of the scan's own passive evidence.

Targets are only IP addresses that an in-scope name resolves to (an edge `resolves_to` from an in-scope name, backed by a
DNS evidence record): never a neighbour on the same network, never a range, never a candidate. Each address is then
refused (private, loopback, link-local, reserved, IPv6) or skipped (a shared platform) with the reason recorded.
The ports are those a passive source says are open on that address plus a short fixed list (scrutator.active), capped.

Because the plan is a pure function of the report's entities, edges and evidence and of the shared-platform pack, `verify`
re-derives it from a bundle and checks that no probe went to an address or port outside it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from scrutator.active import PORT_REASONS, RISKY_PORTS, WEB_PORTS
from scrutator.active.guard import Limits, refusal, shared_platform
from scrutator.exposure import exposure
from scrutator.packs import PackSet
from scrutator.risk.view import View
from scrutator.scope import ScopePolicy

PLAN_VERSION = 1


@dataclass
class Plan:
    targets: list[dict] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    over_cap: list[dict] = field(default_factory=list)
    limits: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "version": PLAN_VERSION,
            "limits": self.limits,
            "fixed_ports": [*RISKY_PORTS, *WEB_PORTS],
            "targets": self.targets,
            "skipped": self.skipped,
            "over_cap": self.over_cap,
        }

    def allowed(self) -> dict[str, set[int]]:
        """address -> the ports a connect check may be made on."""
        return {t["ip"]: {p["port"] for p in t["ports"]} for t in self.targets}

    def names_of(self, ip: str) -> list[str]:
        return next((t["probe_names"] for t in self.targets if t["ip"] == ip), [])


def _name_order(name: str) -> tuple:
    return (name.count("."), name)


def resolutions(report: dict, policy: ScopePolicy) -> dict[str, dict]:
    """address -> {names, evidence_ids}: the in-scope names that resolve to it, with the DNS records that say so. Only
    an edge from an entity in state `in` that the scope allows counts, and only when a DNS evidence record backs it."""
    entities = {e["id"]: e for e in report["entities"]}
    found: dict[str, dict] = {}
    for edge in report["edges"]:
        if edge["rel"] != "resolves_to":
            continue
        src, dst = entities.get(edge["src"]), entities.get(edge["dst"])
        if src is None or dst is None or src["type"] != "domain" or dst["type"] != "ip" or src["state"] != "in":
            continue
        if not policy.decide(src["value"]).allowed:
            continue
        backing = [i for i in edge["evidence_ids"] if i in report["evidence"] and report["evidence"][i]["source"] == "dns"]
        if not backing:
            continue
        row = found.setdefault(dst["value"], {"names": set(), "evidence_ids": set()})
        row["names"].add(src["value"])
        row["evidence_ids"].update(backing)
    return found


def plan_active(report: dict, packs: PackSet, limits: Limits | None = None, relax: frozenset[str] = frozenset()) -> Plan:
    """The plan for a report (any dict with `scope`, `entities`, `edges` and `evidence`)."""
    limits = limits or Limits()
    plan = Plan(limits=limits.record())
    if not report.get("scope"):
        return plan
    policy = ScopePolicy(**report["scope"])
    view = View(report, packs)
    rows = {row["ip"]: row for row in exposure(report)}
    entities = {e["id"]: e for e in report["entities"]}
    announced: dict[str, set[str]] = {}
    for edge in report["edges"]:
        if edge["rel"] == "announced_by" and edge["src"] in entities and edge["dst"] in entities:
            announced.setdefault(entities[edge["src"]]["value"], set()).add(entities[edge["dst"]]["value"])

    candidates: list[dict] = []
    for ip, found in sorted(resolutions(report, policy).items()):
        names = sorted(found["names"], key=_name_order)
        evidence_ids = sorted(found["evidence_ids"])
        reason = refusal(ip, relax)
        if reason:
            plan.skipped.append({"ip": ip, "names": names, "kind": "refused-address", "reason": reason, "evidence_ids": evidence_ids})
            continue
        row = rows.get(ip, {})
        hosts = [t for n in names for t in view.targets("CNAME", n)] + list(row.get("hostnames") or [])
        hit = shared_platform(
            packs, address=ip, asns=announced.get(ip, ()), hosts=hosts,
            netnames=[row.get("netname", ""), row.get("description", "")],
        )
        if hit is not None:
            entry, signal = hit
            plan.skipped.append({
                "ip": ip, "names": names, "kind": "shared-platform", "platform": entry.platform, "signal": signal,
                "verified": entry.verified, "evidence_ids": evidence_ids,
                "reason": f"{entry.platform} serves many customers from this address ({signal}); it is not probed",
            })
            continue
        passive = sorted({p for p in row.get("ports", []) if isinstance(p, int) and 1 <= p <= 65535})
        risky_first = [p for p in passive if p in RISKY_PORTS]
        order = list(dict.fromkeys([*risky_first, *WEB_PORTS, *passive, *RISKY_PORTS]))
        candidates.append({
            "ip": ip, "names": names, "probe_names": names[: limits.max_names_per_ip], "evidence_ids": evidence_ids,
            "passive_ports": passive,
            "passive_evidence_ids": sorted(i for i in row.get("evidence_ids", []) if report["evidence"][i]["source"] == "internetdb"),
            "_order": order,
        })

    # the connect-check budget is shared out one port at a time across the addresses, so one address with a long list of
    # open ports cannot use up the checks of the others
    chosen: dict[str, list[int]] = {c["ip"]: [] for c in candidates}
    left = limits.tcp_budget
    depth = 0
    while left > 0 and any(depth < len(c["_order"]) for c in candidates):
        for c in candidates:
            if depth < len(c["_order"]) and left > 0:
                chosen[c["ip"]].append(c["_order"][depth])
                left -= 1
        depth += 1
    for c in candidates:
        ports = sorted(chosen[c["ip"]])
        for port in c.pop("_order"):
            if port not in ports:
                plan.over_cap.append({"ip": c["ip"], "port": port})
        passive = set(c["passive_ports"])
        c["ports"] = [
            {"port": p, "why": ("passive source lists it open; " if p in passive else "") + PORT_REASONS.get(p, "listed open by a passive source")}
            for p in ports
        ]
        plan.targets.append(c)
    plan.over_cap.sort(key=lambda o: (o["ip"], o["port"]))
    return plan
