"""Hygiene rules: dangling CNAMEs, SPF, DMARC, CAA, domain expiry, forgotten-looking names.

Each rule reads only the View (in-scope evidence) and returns Risks. A rule that needs a
negative result (no CAA, no DMARC, NXDOMAIN) fires only when the scan recorded that negative as
evidence; a lookup that never ran or that failed is silence, not a finding.
"""

import re
from datetime import timedelta

from scrutator.model import Confidence
from scrutator.risk.catalog import make
from scrutator.risk.model import Risk, Severity
from scrutator.risk.view import View, parse_time, txt_values

FORGOTTEN_WORDS = frozenset(
    {"dev", "test", "testing", "stage", "staging", "old", "backup", "bak", "temp", "tmp",
     "demo", "uat", "qa", "beta", "legacy", "internal", "preprod", "sandbox"}
)
_LOOKUP_TERMS = frozenset({"include", "a", "mx", "ptr", "exists"})
_SHOWN = 200


def _shown(text: str) -> str:
    return text if len(text) <= _SHOWN else text[: _SHOWN - 3] + "..."


def _id(name: str) -> str:
    return f"domain:{name}"


def _ancestors(name: str, names: set[str]) -> list[str]:
    parts = name.split(".")
    return [".".join(parts[i:]) for i in range(1, len(parts) - 1) if ".".join(parts[i:]) in names]


# dangling CNAME -------------------------------------------------------------------------


def dangling_cnames(view: View) -> list[Risk]:
    risks = []
    for name in sorted(view.names):
        targets = view.targets("CNAME", name)
        address = view.dns("A", name)
        if not targets or address is None or address.answer.status != "nxdomain":
            continue
        target = targets[0]
        if target in view.names and view.answers("CNAME", target):
            continue  # the chain continues inside the scope; the end of it is reported
        evidence = [address.evidence_id, view.dns("CNAME", name).evidence_id]
        entry = view.packs.match_takeover(target)
        base = f"{name} is an alias (CNAME) of {target}, and the address lookup for {name} returned NXDOMAIN, so the target does not exist."
        entities = [_id(name), _id(target)]
        if entry is not None and entry.status == "vulnerable" and entry.dangling == "nxdomain":
            risks.append(
                make(
                    "dangling-cname-claimable", entities, evidence,
                    f"{base} {target} matches the takeover fingerprint {entry.id} ({entry.provider}, rated {entry.status}, shown by NXDOMAIN).",
                    Confidence.HIGH if entry.verified else Confidence.MEDIUM,
                )
            )
        elif entry is not None:
            risks.append(
                make(
                    "dangling-cname-known-service", entities, evidence,
                    f"{base} {target} matches the takeover fingerprint {entry.id} ({entry.provider}, rated {entry.status}, shown by {entry.dangling}).",
                    Confidence.MEDIUM,
                )
            )
        else:
            risks.append(make("dangling-cname", entities, evidence, base, Confidence.MEDIUM))
    return risks


# SPF --------------------------------------------------------------------------------------


def _spf_terms(value: str) -> list[str]:
    return value.split()[1:]


def spf_weaknesses(view: View) -> list[Risk]:
    risks = []
    for name in sorted(view.names):
        record = view.dns("TXT", name)
        if record is None:
            continue
        spf = [v for v in txt_values(view.answers("TXT", name)) if v.lower().startswith("v=spf1")]
        if not spf:
            continue
        entities, evidence = [_id(name)], [record.evidence_id]
        if len(spf) > 1:
            risks.append(
                make("spf-multiple-records", entities, evidence,
                     f"{name} publishes {len(spf)} TXT records that start with v=spf1.", Confidence.HIGH)
            )
            continue
        value = spf[0]
        terms = _spf_terms(value)
        final = [t for t in terms if re.fullmatch(r"[+\-~?]?all", t.lower())]
        redirect = any(t.lower().startswith("redirect=") for t in terms)
        lookups = sum(
            1 for t in terms
            if t.lower().startswith("redirect=")
            or re.split(r"[:/]", t.lstrip("+-~?").lower(), maxsplit=1)[0] in _LOOKUP_TERMS
        )
        quoted = f'{name} publishes the SPF record "{_shown(value)}"'
        if final:
            qualifier = final[-1][0] if final[-1][0] in "+-~?" else "+"
            if qualifier == "+":
                risks.append(make("spf-allows-all", entities, evidence, f'{quoted}, which ends with "{final[-1]}".', Confidence.HIGH))
            elif qualifier == "?":
                risks.append(make("spf-neutral-all", entities, evidence, f'{quoted}, which ends with "{final[-1]}".', Confidence.HIGH))
            elif qualifier == "~":
                risks.append(make("spf-softfail-all", entities, evidence, f'{quoted}, which ends with "{final[-1]}".', Confidence.HIGH))
        elif not redirect:
            risks.append(make("spf-no-all", entities, evidence, f"{quoted}, which has no all mechanism and no redirect.", Confidence.HIGH))
        if lookups > 10:
            risks.append(
                make("spf-too-many-lookups", entities, evidence,
                     f"{quoted}, whose own terms contain {lookups} mechanisms that cause a DNS lookup.", Confidence.HIGH)
            )
    return risks


# DMARC ------------------------------------------------------------------------------------


def _dmarc(view: View, name: str) -> str | None:
    for value in txt_values(view.answers("TXT", f"_dmarc.{name}")):
        if value.lower().startswith("v=dmarc1"):
            return value
    return None


def _policy(value: str) -> str:
    for part in value.split(";"):
        key, _, setting = part.partition("=")
        if key.strip().lower() == "p":
            return setting.strip().lower()
    return ""


def dmarc_gaps(view: View) -> list[Risk]:
    risks = []
    for name in sorted(view.names):
        own = view.dns("TXT", f"_dmarc.{name}")
        if own is None:
            continue
        value = _dmarc(view, name)
        if value is not None:
            if _policy(value) == "none":
                risks.append(
                    make("dmarc-monitoring-only", [_id(name)], [own.evidence_id],
                         f'_dmarc.{name} publishes "{_shown(value)}", whose policy is p=none.', Confidence.HIGH)
                )
            continue
        mail = view.dns("MX", name)
        if not view.targets("MX", name):
            continue  # not a mail domain: a missing DMARC record is not a finding
        if not own.answer.negative and own.answer.status != "answer":
            continue
        if any(_dmarc(view, parent) is not None for parent in _ancestors(name, view.names)):
            continue  # a parent domain's record applies
        what = "returned NXDOMAIN" if own.answer.status == "nxdomain" else "returned no DMARC record"
        risks.append(
            make("dmarc-missing", [_id(name)], [mail.evidence_id, own.evidence_id],
                 f"{name} has MX records, and the TXT lookup for _dmarc.{name} {what}.", Confidence.HIGH)
        )
    return risks


# CAA --------------------------------------------------------------------------------------


def caa_gaps(view: View) -> list[Risk]:
    risks = []
    for apex in view.zone_apexes():
        caa = view.dns("CAA", apex)
        if caa is None or not caa.answer.negative:
            continue
        if any(view.answers("CAA", parent) for parent in _ancestors(apex, view.names)):
            continue  # the parent zone's CAA records apply to this name too
        risks.append(
            make("caa-missing", [_id(apex)], [caa.evidence_id, view.dns("NS", apex).evidence_id],
                 f"{apex} has name server records and the CAA lookup for {apex} returned "
                 f"{'NXDOMAIN' if caa.answer.status == 'nxdomain' else 'no record'}.", Confidence.HIGH)
        )
    return risks


# domain expiry ----------------------------------------------------------------------------


def domain_expiry(view: View) -> list[Risk]:
    risks = []
    for name in sorted(view.rdap):
        info = view.rdap[name]
        events = info["data"].get("events", [])
        dates = [
            e.get("eventDate") for e in events
            if isinstance(e, dict) and str(e.get("eventAction", "")).lower() == "expiration"
        ]
        expiry = parse_time(dates[0]) if dates else None
        collected = parse_time(info["collected_at"])
        if expiry is None or collected is None:
            continue
        remaining = expiry - collected
        entities, evidence = [_id(name)], [info["evidence_id"]]
        stamp = f"RDAP lists the expiration of {name} as {dates[0]}; the data was collected {info['collected_at']}"
        if remaining < timedelta(0):
            risks.append(make("domain-expired", entities, evidence, f"{stamp}, after that date.", Confidence.HIGH))
        elif remaining <= timedelta(days=30):
            severity = Severity.HIGH if remaining <= timedelta(days=14) else Severity.MEDIUM
            risks.append(
                make("domain-expiring", entities, evidence, f"{stamp}, {remaining.days} day(s) before it.", Confidence.HIGH, severity=severity)
            )
    return risks


# forgotten-looking names --------------------------------------------------------------------


def forgotten_names(view: View) -> list[Risk]:
    risks = []
    for name in sorted(view.names):
        labels = name.split(".")[:-2]  # the registered domain's own labels never count
        hit = next(
            (
                label for label in labels
                if any(re.sub(r"\d+$", "", token) in FORGOTTEN_WORDS for token in re.split(r"[-_]", label))
            ),
            None,
        )
        if hit is None:
            continue
        for rtype in ("A", "AAAA"):
            addresses = view.answers(rtype, name)
            if addresses:
                risks.append(
                    make("forgotten-name", [_id(name)], [view.dns(rtype, name).evidence_id],
                         f'{name} contains the label "{hit}" and resolves to {", ".join(addresses)}.', Confidence.LOW)
                )
                break
    return risks


HYGIENE_RULES = (dangling_cnames, spf_weaknesses, dmarc_gaps, caa_gaps, domain_expiry, forgotten_names)
