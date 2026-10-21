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

Next to the state, each name has a **tier**: how well the evidence supports the claim that the name
exists. The state says what DNS answered; the tier also weighs who else names it and when.

- `verified`: DNS resolves it (an address, or any other record), or a certificate or an observation
  with a timestamp inside the recent window (`RECENT_DAYS` before the record was collected) names it
  and no DNS answer contradicts it (a wildcard zone does not count as a contradiction).
- `claimed`: only a list names it (an aggregator, an archive, the DNS records of other names) and DNS
  gives no sign of it. The bulk of a long list lives here.
- `stale`: it was evidenced once (a certificate or observation, however old) and DNS no longer agrees:
  NXDOMAIN, or no answer and the record is older than the window.
- `wildcard`: only a wildcard zone answers for it, and nothing dated vouches for it.

Nothing is deleted: every tier stays in the report, claimed names with the reason they are claims.

A pure function of the report's own entities, edges and evidence, so `scrutator verify` recomputes it.
Only in-scope names are described; evidence about any other name is ignored.
"""

import json
import re
from datetime import datetime, timedelta, timezone

from scrutator.model.canonical import canonical_host
from scrutator.resolver import parse_payload
from scrutator.scope import ScopePolicy

STATES = ("live", "stale", "wildcard", "unresolved")
TIERS = ("verified", "claimed", "stale", "wildcard")
RECENT_DAYS = 90
# Sources whose record for a name carries a timestamp that says it was in use: certificates (valid
# until `not_after`) and a scan that fetched the host (`task.time`). Every other naming source is a list.
_CERT_SOURCES = frozenset({"crtsh", "certspotter"})
_OBSERVED_SOURCES = frozenset({"urlscan"})
_ZONE_SOURCES = frozenset({"axfr"})  # an authoritative copy of the zone (R6, opt-in)
_DNS = re.compile(r"DNS (A|AAAA|CNAME|MX|NS|TXT) (\S+)")
_OTHER_RECORDS = ("CNAME", "MX", "NS", "TXT")
_PROBE = re.compile(r"wc-probe-[0-9a-f]{12}\.(\S+)")
_NAMING_RELS = frozenset({"has_subdomain", "related_host", "known_as", "mentions", "reverse_dns"})
_MAX_AHEAD = timedelta(days=800)  # no certificate lasts this long: a later date is not a date to believe


def _when(raw: object) -> datetime | None:
    if not isinstance(raw, str):
        return None
    try:
        stamp = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)


def _dated(source: str, payload: str, collected: datetime) -> datetime | None:
    """The latest timestamp a naming record carries (a certificate's `not_after`, the time of a scan),
    or None for a record without a believable one: evidence collected from public sources is untrusted."""
    try:
        rows = json.loads(payload)
    except ValueError:
        return None
    if not isinstance(rows, list):
        return None
    stamps = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if source in _CERT_SOURCES:
            raw = row.get("not_after")
        else:
            task = row.get("task")
            raw = task.get("time") if isinstance(task, dict) else None
        stamp = _when(raw)
        if stamp is not None and stamp <= collected + _MAX_AHEAD:
            stamps.append(stamp)
    return max(stamps) if stamps else None


def _vouchers(report: dict, ids: dict[str, str]) -> dict[str, list[dict]]:
    """Dated records that name each in-scope name: kind, time, whether inside the recent window."""
    found: dict[str, dict[str, dict]] = {}
    for edge in report["edges"]:
        name = ids.get(edge["dst"])
        if name is None or edge["rel"] not in _NAMING_RELS:
            continue
        for evidence_id in edge["evidence_ids"]:
            record = report["evidence"].get(evidence_id)
            if not record or record["source"] not in _CERT_SOURCES | _OBSERVED_SOURCES:
                continue
            collected = _when(record.get("collected_at"))
            if collected is None:
                continue
            at = _dated(record["source"], record["payload"], collected)
            if at is None:
                continue
            found.setdefault(name, {})[evidence_id] = {
                "id": evidence_id,
                "kind": "certificate" if record["source"] in _CERT_SOURCES else "observation",
                "at": at,
                "recent": at >= collected - timedelta(days=RECENT_DAYS),
            }
    return {
        name: sorted(items.values(), key=lambda v: (v["at"], v["kind"], v["id"])) for name, items in found.items()
    }


def _what(voucher: dict) -> str:
    day = voucher["at"].date().isoformat()
    if voucher["kind"] == "certificate":
        return f"a certificate naming it (valid until {day})"
    return f"a scan of it on {day}"


def _dns_record_reason(records: dict[str, str]) -> str:
    return f"DNS holds a {', '.join(sorted(records))} record for it, though no address was recorded"


def _tier(
    state: str, reason: str, named_by: list[str], vouchers: list[dict], records: dict[str, str]
) -> tuple[str, str | None, str, list[str]]:
    """(tier, basis, why, extra evidence ids) for one name, from its DNS state and the dated records
    that name it. DNS is read first: an address verifies a name, NXDOMAIN keeps a dated record from
    doing so, and silence (no answer) leaves the name to the records."""
    recent = [v for v in vouchers if v["recent"]]
    if state == "live":
        return "verified", "dns", reason, []
    if state in ("unresolved", "wildcard") and set(named_by) & _ZONE_SOURCES:
        # the zone's own name server listed it in a zone transfer (opt-in --axfr): authoritative, whatever has an address
        return "verified", "zone", "the zone's own name server lists it (zone transfer)", []
    if state == "unresolved" and records:
        return "verified", "dns", _dns_record_reason(records), sorted(records.values())
    if state in ("unresolved", "wildcard") and recent:
        best = recent[-1]
        note = (
            "DNS shows only the zone's wildcard, which proves nothing either way"
            if state == "wildcard"
            else "DNS recorded no address, which does not contradict it"
        )
        return "verified", best["kind"], f"{_what(best)} is inside the {RECENT_DAYS}-day window; {note}", [
            v["id"] for v in recent
        ]
    if state == "wildcard":
        return "wildcard", None, reason, []
    if vouchers:
        last = vouchers[-1]
        if state == "stale":
            why = f"{_what(last)} existed, but the address lookup returned NXDOMAIN"
        else:
            why = f"{_what(last)} is older than the {RECENT_DAYS}-day window and DNS recorded no address"
        return "stale", None, why, [v["id"] for v in vouchers]
    who = ", ".join(named_by) if named_by else "no list"
    verb = "names" if len(named_by) <= 1 else "name"
    dns = "the address lookup returned NXDOMAIN" if state == "stale" else "DNS recorded no address for it"
    return "claimed", None, f"only {who} {verb} it, and {dns}", []


def name_states(report: dict, *, tiered: bool = True) -> list[dict]:
    """The rows described above. `tiered=False` gives the v0.6 shape (no tier, evidence of the DNS
    answers only, sorted by name), which is what a bundle made before tiers existed holds."""
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
            if answer.status == "answer" and rtype in ("A", "AAAA"):
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
    vouchers = _vouchers(report, {entity_id: name for name, entity_id in names.items()})

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
        records = {
            rtype: answers[(rtype, name)][1]
            for rtype in _OTHER_RECORDS
            if (rtype, name) in answers and answers[(rtype, name)][0].status == "answer"
        }
        sources = sorted(named_by.get(names[name], ()))
        row = {
            "name": name,
            "state": state,
            "reason": reason,
            "addresses": listed,
            "named_by": sources,
            "evidence_ids": sorted(set(evidence_ids)),
        }
        if tiered:
            tier, basis, why, extra = _tier(state, reason, sources, vouchers.get(name, []), records)
            row.update(tier=tier, basis=basis, tier_reason=why, evidence_ids=sorted(set(evidence_ids) | set(extra)))
        rows.append(row)
    if tiered:
        rows.sort(key=lambda row: (TIERS.index(row["tier"]), row["name"]))
    return rows


def summarise_states(rows: list[dict]) -> dict[str, int]:
    return {state: sum(1 for row in rows if row["state"] == state) for state in STATES}


def summarise_tiers(rows: list[dict]) -> dict[str, int]:
    return {tier: sum(1 for row in rows if row["tier"] == tier) for tier in TIERS}


def headline(tiers: dict[str, int]) -> str:
    """The number to quote for a scan: how many names are evidenced and how many are only claimed, with
    the two groups that DNS or a wildcard has set aside counted next to them."""
    return (
        f"{tiers['verified']} verified, {tiers['claimed']} claimed "
        f"({tiers['stale']} stale, {tiers['wildcard']} wildcard-covered)"
    )
