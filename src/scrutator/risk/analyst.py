"""Analyst detectors (spec section 11, layer 1): deterministic checks for things a human
reviewer skips because they are subtle, spread across sources, or about something absent.

No AI is involved. Each detector returns Risks tagged category "analyst", and each cites the
evidence it rests on, including the evidence of absence (an NXDOMAIN, a differing name server
list) that makes the oddity visible.
"""

import re

from scrutator.model import Confidence
from scrutator.risk.catalog import make
from scrutator.risk.model import Risk
from scrutator.risk.view import View, host

_NUMBERED = re.compile(r"([a-z][a-z_-]*?)(\d{1,4})")
_MAX_SPAN = 50


def ghost_hostnames(view: View) -> list[Risk]:
    """A certificate or archive names a host in scope, DNS says it does not exist, and it is
    not an alias (an alias to nowhere is the dangling-CNAME rule's business)."""
    risks = []
    named = view.named_by()
    for name in sorted(named):
        address = view.dns("A", name)
        if address is None or address.answer.status != "nxdomain" or view.answers("CNAME", name):
            continue
        sources = named[name]
        kinds = sorted({source for source, _ in sources})
        risks.append(
            make(
                "ghost-hostname", [f"domain:{name}"], [*(e for _, e in sources[:4]), address.evidence_id],
                f"{name} is named by {', '.join(kinds)}, and the address lookup for {name} returned NXDOMAIN.",
                Confidence.MEDIUM if len(kinds) >= 2 else Confidence.LOW,
            )
        )
    return risks


def numbering_gaps(view: View) -> list[Risk]:
    """Names such as app1, app2, app4: a number in the middle of a series is missing."""
    groups: dict[tuple[str, str], dict[int, tuple[str, str]]] = {}
    for name in sorted(view.names):
        label, _, rest = name.partition(".")
        match = _NUMBERED.fullmatch(label)
        if match and rest:
            groups.setdefault((match.group(1), rest), {})[int(match.group(2))] = (name, match.group(2))
    risks = []
    for (prefix, rest), members in sorted(groups.items()):
        low, high = min(members), max(members)
        gaps = [n for n in range(low, high + 1) if n not in members]
        if len(members) < 3 or not gaps or high - low > _MAX_SPAN:
            continue
        pad = max((len(digits) for _, digits in members.values() if digits.startswith("0")), default=0)
        present = [members[n][0] for n in sorted(members)]
        evidence = []
        for name in present[:6]:
            incoming = view.edges_into(f"domain:{name}")
            if incoming and incoming[0]["evidence_ids"]:
                evidence.append(incoming[0]["evidence_ids"][0])
            elif view.dns("A", name) is not None:
                evidence.append(view.dns("A", name).evidence_id)
        if not evidence:
            continue
        missing = [f"{prefix}{str(n).zfill(pad)}.{rest}" for n in gaps[:5]]
        risks.append(
            make(
                "numbering-gap", [f"domain:{n}" for n in present[:10]], evidence,
                f"{len(present)} names follow the pattern {prefix}<number>.{rest} ({', '.join(present[:6])}); "
                f"the number(s) {', '.join(str(n) for n in gaps[:5])} are missing, for example {missing[0]}.",
                Confidence.LOW,
            )
        )
    return risks


def source_disagreement(view: View) -> list[Risk]:
    """The registry (RDAP) and the zone itself list different name servers for a domain."""
    risks = []
    for name in sorted(view.rdap):
        info = view.rdap[name]
        listed = info["data"].get("nameservers", [])
        registry = {host(n["ldhName"]) for n in listed if isinstance(n, dict) and n.get("ldhName")}
        zone = set(view.targets("NS", name))
        if not registry or not zone or registry == zone:
            continue
        only_registry, only_zone = sorted(registry - zone), sorted(zone - registry)
        parts = []
        if only_registry:
            parts.append(f"only RDAP lists {', '.join(only_registry)}")
        if only_zone:
            parts.append(f"only the zone's NS records list {', '.join(only_zone)}")
        risks.append(
            make(
                "source-disagreement", [f"domain:{name}"], [info["evidence_id"], view.dns("NS", name).evidence_id],
                f"For {name}, {' and '.join(parts)}.", Confidence.MEDIUM,
            )
        )
    return risks


ANALYST_RULES = (ghost_hostnames, numbering_gaps, source_disagreement)
