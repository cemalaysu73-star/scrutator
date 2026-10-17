"""The state of every in-scope hostname, from the DNS evidence the scan holds.

A certificate or an archive names a host that may have been retired years ago, so a list of names is
not a list of hosts. Each in-scope name gets one of four states:

- `live`: an A or AAAA answer was recorded for it.
- `stale`: the address lookup answered NXDOMAIN.
- `wildcard`: it resolves, but only to addresses that a random label under the same apex also resolves
  to, so the zone would answer for the name whether or not it exists. Another source (a certificate)
  may still vouch for it: `named_by` lists who names it.
- `unresolved`: no address and no NXDOMAIN was recorded: the name exists without an address, or the
  lookup did not run or failed. Silence is never read as a negative.

A pure function of the report's own entities, edges and evidence, so `scrutator verify` recomputes it.
Only in-scope names are described; evidence about any other name is ignored.
"""

import re

from scrutator.model.canonical import canonical_host
from scrutator.resolver import parse_payload
from scrutator.scope import ScopePolicy

STATES = ("live", "stale", "wildcard", "unresolved")
_DNS = re.compile(r"DNS (A|AAAA) (\S+)")
_PROBE = re.compile(r"wc-probe-[0-9a-f]{12}\.(\S+)")
_NAMING_RELS = frozenset({"has_subdomain", "related_host", "known_as"})


def name_states(report: dict) -> list[dict]:
    scope = report.get("scope")
    policy = ScopePolicy(**scope) if scope else None
    names = {
        e["value"]: e["id"]
        for e in report["entities"]
        if e["type"] == "domain" and e["state"] == "in" and (policy is None or policy.decide(e["value"]).allowed)
    }
    answers: dict[tuple[str, str], tuple[object, str]] = {}  # (rtype, name) -> (answer, evidence id)
    probes: dict[str, dict] = {}  # zone -> {"addresses": set, "evidence_ids": list}
    for evidence_id in sorted(report["evidence"]):
        record = report["evidence"][evidence_id]
        if record["source"] != "dns":
            continue
        match = _DNS.fullmatch(record["request"])
        if not match:
            continue
        rtype, raw = match.groups()
        try:
            name = canonical_host(raw)
        except ValueError:
            continue
        answer = parse_payload(record["payload"])
        probe = _PROBE.fullmatch(name)
        if probe:
            if answer.status == "answer":
                zone = probes.setdefault(probe.group(1), {"addresses": set(), "evidence_ids": []})
                zone["addresses"].update(answer.records)
                zone["evidence_ids"].append(evidence_id)
        elif name in names:
            answers.setdefault((rtype, name), (answer, evidence_id))

    named_by: dict[str, set[str]] = {}
    for edge in report["edges"]:
        if edge["rel"] in _NAMING_RELS:
            for evidence_id in edge["evidence_ids"]:
                source = report["evidence"].get(evidence_id, {}).get("source")
                if source and source != "dns":
                    named_by.setdefault(edge["dst"], set()).add(source)

    rows = []
    for name in sorted(names):
        addresses: set[str] = set()
        evidence_ids: list[str] = []
        for rtype in ("A", "AAAA"):
            found = answers.get((rtype, name))
            if found and found[0].status == "answer":
                addresses.update(found[0].records)
                evidence_ids.append(found[1])
        listed = sorted(addresses)
        if addresses:
            wild: set[str] = set()
            wild_evidence: list[str] = []
            for zone, probe in probes.items():
                if name.endswith("." + zone):
                    wild |= probe["addresses"]
                    wild_evidence += probe["evidence_ids"]
            if wild and addresses <= wild:
                state = "wildcard"
                reason = (
                    f"resolves to {', '.join(listed)}, which a random label under the same zone also resolves to: "
                    "the zone would answer for this name whether or not it exists"
                )
                evidence_ids += wild_evidence
            else:
                state, reason = "live", f"resolves to {', '.join(listed)}"
        else:
            nx = answers.get(("A", name))
            if nx and nx[0].status == "nxdomain":
                state, reason = "stale", "the address lookup returned NXDOMAIN"
                evidence_ids.append(nx[1])
            else:
                state = "unresolved"
                reason = "no address and no NXDOMAIN was recorded: no address record, or the lookup did not run"
        rows.append(
            {
                "name": name,
                "state": state,
                "reason": reason,
                "addresses": listed,
                "named_by": sorted(named_by.get(names[name], ())),
                "evidence_ids": sorted(set(evidence_ids)),
            }
        )
    return rows


def summarise_states(rows: list[dict]) -> dict[str, int]:
    return {state: sum(1 for row in rows if row["state"] == state) for state in STATES}
