"""What an audit says, derived from a report (and the bundle's audit log) by deterministic code.

`build_audit` returns the audit's facts: a JSON-serialisable dictionary from which `render_audit` writes the HTML. The
same inputs always give the same facts, so `scrutator audit-check` can rebuild them from the signed bundle and compare.
Every statement about the client's infrastructure (an executive sentence of kind `fact`, a risk, an inventory row)
carries the ids of the evidence records it rests on; `scope` sentences describe the review itself, not the client.
"""

from __future__ import annotations

from datetime import date

from scrutator import __version__
from scrutator.audit.i18n import EFFORT, EFFORT_RANK, RULES_TR, TEXT, plural
from scrutator.risk.engine import RULESET_VERSION

FORMAT = "scrutator-audit/1"
MAX_INVENTORY = 200
MAX_CITED = 400
_SEV_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}
_CONF_RANK = {"high": 2, "medium": 1, "low": 0}


class AuditError(ValueError):
    """The audit cannot be made: no authorisation, a scope the authorisation does not cover, a bundle that fails."""


# ------------------------------------------------------------------------------------------- authorisation


def authorisation_from_log(audit_records: list[dict]) -> dict | None:
    """The authorisation the scan's signed audit log records before its first lookup: an engagement (client mode) or a
    self-attestation (self mode). None when it records neither, or records it only after a lookup."""
    first_lookup = next((i for i, r in enumerate(audit_records) if r.get("module")), len(audit_records))
    for index, record in enumerate(audit_records[:first_lookup]):
        if record.get("event") == "engagement":
            return {
                "mode": "client", "recorded": "signed", "sha256": str(record.get("sha256") or ""),
                "organisation": record.get("organisation"), "domains": list(record.get("domains") or []),
                "authorised_by": record.get("authorised_by") or {}, "start": record.get("start"), "end": record.get("end"),
                "purpose": record.get("purpose"), "reference": str(record.get("reference") or ""),
            }
        if record.get("event") == "self_attestation":
            return {
                "mode": "self", "recorded": "signed", "sha256": "", "organisation": record.get("organisation") or "",
                "domains": list(record.get("domains") or []), "authorised_by": {}, "start": None, "end": None,
                "purpose": "", "reference": str(record.get("reference") or ""),
            }
    return None


def engagement_event(loaded, confirmed: str) -> dict:
    """The audit-log record of an engagement, as `scrutator exposure` writes it, plus the engagement's reference."""
    return {"event": "engagement", "sha256": loaded.sha256, **loaded.engagement.record(), "confirmed": confirmed,
            "reference": loaded.engagement.reference}


def self_event(domains: list[str], organisation: str, confirmed: str) -> dict:
    return {
        "event": "self_attestation", "domains": list(domains), "organisation": organisation, "confirmed": confirmed,
        "statement": "the person running this scan owns or controls these domains",
    }


def authorisation_late(loaded=None, *, domains: list[str] | None = None, organisation: str = "") -> dict:
    """An authorisation recorded when the report is made, for a bundle whose log does not hold one."""
    if loaded is None:
        return {"mode": "self", "recorded": "report-time", "sha256": "", "organisation": organisation, "domains": list(domains or []),
                "authorised_by": {}, "start": None, "end": None, "purpose": "", "reference": ""}
    record = loaded.engagement.record()
    return {"mode": "client", "recorded": "report-time", "sha256": loaded.sha256, "organisation": record["organisation"],
            "domains": record["domains"], "authorised_by": record["authorised_by"], "start": record["start"], "end": record["end"],
            "purpose": record["purpose"], "reference": loaded.engagement.reference}


def covered(domains: list[str], host: str) -> bool:
    host = str(host).lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in domains)


def check_authorisation(report: dict, authorisation: dict) -> None:
    """The scan's seed and every domain of its scope must be inside the authorisation, and a client engagement must have
    been in force on the day the scan ran."""
    domains = [str(d).lower() for d in authorisation.get("domains") or []]
    if not domains:
        raise AuditError("the authorisation names no domain")
    seed = str(report["scan"]["seed"])
    scope_domains = list((report.get("scope") or {}).get("domains") or [])
    outside = [d for d in [seed, *scope_domains] if not covered(domains, d)]
    if outside:
        raise AuditError(f"{outside[0]} is in the scan's scope but not in the authorisation ({', '.join(domains)})")
    if authorisation["mode"] == "client":
        started = str(report["scan"].get("started_at") or "")[:10]
        try:
            day = date.fromisoformat(started)
        except ValueError as exc:
            raise AuditError("the scan has no start date to check against the engagement") from exc
        if not (str(authorisation["start"]) <= day.isoformat() <= str(authorisation["end"])):
            raise AuditError(f"the scan ran on {day}, outside the engagement ({authorisation['start']} to {authorisation['end']})")


# ------------------------------------------------------------------------------------------- the facts


def _value(entity_id: str) -> str:
    return entity_id.split(":", 1)[1] if ":" in entity_id else entity_id


def _rule_text(rule: str, lang: str, title: str, remediation: str) -> tuple[str, str]:
    if lang == "tr" and rule in RULES_TR:
        return RULES_TR[rule]
    return title, remediation


def _risks(report: dict, lang: str, packs) -> list[dict]:
    rows = []
    for risk in report.get("risks") or []:
        effort = EFFORT.get(risk["rule_id"], "medium")
        title, fix = _rule_text(risk["rule_id"], lang, risk["title"], risk["remediation"])
        entry = packs.compliance_for(risk["rule_id"]) if packs is not None else None
        rows.append({
            "rule_id": risk["rule_id"], "severity": risk["severity"], "category": risk["category"], "confidence": risk["confidence"],
            "title": title, "affected": [_value(e) for e in risk["entity_ids"]], "explanation": risk["explanation"],
            "remediation": fix, "effort": effort, "evidence_ids": list(risk["evidence_ids"]), "fingerprint": risk["fingerprint"],
            "compliance": [m.model_dump(mode="json") for m in entry.mappings] if entry is not None else [],
        })
    rows.sort(key=lambda r: (-_SEV_RANK[r["severity"]], -_CONF_RANK.get(r["confidence"], 0), EFFORT_RANK[r["effort"]], r["rule_id"], r["fingerprint"]))
    for number, row in enumerate(rows, 1):
        row["ref"] = f"R{number}"
        row["priority"] = number
    return rows


def _inventory(report: dict) -> tuple[list[dict], int]:
    providers: dict[str, set[str]] = {}
    for dep in report.get("dependencies") or []:
        for host in dep.get("hostnames") or []:
            providers.setdefault(host, set()).add(f"{dep['provider']} ({dep['category']})")
    networks: dict[str, str] = {}
    for row in report.get("exposure") or []:
        label = row.get("netname") or row.get("description") or ""
        if label:
            networks[row["ip"]] = label + (f", {row['country']}" if row.get("country") else "")
    verified = [r for r in report.get("names") or [] if r.get("tier") == "verified"]
    rows = []
    for name in sorted(verified, key=lambda r: (r["name"].count("."), r["name"])):
        addresses = list(name.get("addresses") or [])
        rows.append({
            "name": name["name"], "addresses": addresses, "providers": sorted(providers.get(name["name"], set())),
            "networks": sorted({networks[a] for a in addresses if a in networks}), "evidence_ids": list(name["evidence_ids"]),
        })
    return rows[:MAX_INVENTORY], len(rows)


def _sources(report: dict) -> list[dict]:
    rows = []
    for name, health in sorted((report.get("sources") or {}).items()):
        if health.get("down"):
            outcome = "down"
        elif health.get("error") and not health.get("ok"):
            outcome = "failed"
        elif health.get("ok"):
            outcome = "ok" if not health.get("error") else "partial"
        else:
            outcome = "idle"
        rows.append({"source": name, "outcome": outcome, "ok": int(health.get("ok", 0)), "error": int(health.get("error", 0)),
                     "errors": [str(e)[:160] for e in (health.get("errors") or [])[:2]]})
    return rows


def _join(items: list[str], limit: int = 3) -> str:
    shown = ", ".join(items[:limit])
    return shown + (f" +{len(items) - limit}" if len(items) > limit else "")


def _executive(report: dict, risks: list[dict], sources: list[dict], auth: dict, who: dict, lang: str) -> list[dict]:
    t = TEXT[lang]
    tiers = (report.get("summary") or {}).get("tiers") or {}
    names = report.get("names") or []
    verified_ids = sorted({i for r in names if r.get("tier") == "verified" for i in r["evidence_ids"]})
    claimed_ids = sorted({i for r in names if r.get("tier") == "claimed" for i in r["evidence_ids"]})
    out = [{"kind": "scope", "text": t["exec_scope"].format(
        auditor=who["auditor"] or t["reviewer"], client=who["client"], domains=", ".join(auth["domains"]), date=str(report["scan"]["started_at"])[:10]),
        "evidence_ids": [], "risk_refs": []}]
    out.append({"kind": "fact", "text": t["exec_verified"].format(n=tiers.get("verified", 0), **plural(lang, tiers.get("verified", 0))), "evidence_ids": verified_ids, "risk_refs": []})
    if tiers.get("claimed"):
        out.append({"kind": "fact", "text": t["exec_claimed"].format(n=tiers["claimed"], **plural(lang, tiers["claimed"])), "evidence_ids": claimed_ids, "risk_refs": []})
    if risks:
        count = {s: sum(1 for r in risks if r["severity"] == s) for s in ("high", "medium", "low", "info")}
        out.append({"kind": "fact", "text": t["exec_risks"].format(n=len(risks), **count, **plural(lang, len(risks))),
                    "evidence_ids": sorted({i for r in risks for i in r["evidence_ids"]}), "risk_refs": [r["ref"] for r in risks]})
        for risk in [r for r in risks if r["severity"] in ("high", "medium")][:3] or risks[:1]:
            fix = risk["remediation"].split(". ")[0].rstrip(".") + "."
            out.append({"kind": "fact", "text": t["exec_top"].format(p=risk["priority"], title=risk["title"], affected=_join(risk["affected"]), fix=fix),
                        "evidence_ids": list(risk["evidence_ids"]), "risk_refs": [risk["ref"]]})
    else:
        out.append({"kind": "fact", "text": t["exec_norisk"].format(n=tiers.get("verified", 0), **plural(lang, tiers.get("verified", 0))), "evidence_ids": verified_ids, "risk_refs": []})
    asked = [s for s in sources if s["outcome"] != "idle"]
    failed = [s for s in asked if s["outcome"] in ("failed", "down", "partial")]
    if failed:
        out.append({"kind": "scope", "text": t["exec_coverage"].format(failed=len(failed), asked=len(asked)), "evidence_ids": [], "risk_refs": []})
    out.append({"kind": "scope", "text": t["exec_proof"], "evidence_ids": [], "risk_refs": []})
    return out


def build_audit(
    report: dict,
    *,
    authorisation: dict,
    bundle: dict,
    lang: str = "en",
    auditor: str = "",
    client: str = "",
    generated_at: str,
    packs=None,
) -> dict:
    """The facts of an audit. `bundle` describes the signed bundle the report comes from: file name, sha256, key
    fingerprint, evidence record count."""
    if lang not in TEXT:
        raise AuditError("language must be en or tr")
    check_authorisation(report, authorisation)
    if packs is None:
        from scrutator.packs import load_packs

        packs = load_packs()
    who = {"auditor": auditor, "client": client or authorisation.get("organisation") or report["scan"]["seed"]}
    risks = _risks(report, lang, packs)
    inventory, verified_total = _inventory(report)
    sources = _sources(report)
    tiers = (report.get("summary") or {}).get("tiers") or {}
    policy = report.get("source_policy") or {}
    coverage = report.get("coverage") or {}
    cited: list[str] = []
    for item in [*risks, *inventory]:
        for evidence_id in item["evidence_ids"]:
            if evidence_id not in cited:
                cited.append(evidence_id)
    evidence = report.get("evidence") or {}
    cited_rows = [
        {"id": i, "source": evidence[i]["source"], "request": str(evidence[i]["request"])[:140], "collected_at": evidence[i]["collected_at"]}
        for i in cited[:MAX_CITED] if i in evidence
    ]
    return {
        "format": FORMAT,
        "tool": __version__,
        "lang": lang,
        "generated_at": generated_at,
        "who": who,
        "authorisation": authorisation,
        "scan": {"id": report["scan"]["id"], "seed": report["scan"]["seed"], "started_at": report["scan"]["started_at"],
                 "report_generated_at": report.get("generated_at"), "tool": (report.get("tool") or {}).get("version")},
        "bundle": bundle,
        "summary": {"verified": tiers.get("verified", 0), "claimed": tiers.get("claimed", 0), "stale": tiers.get("stale", 0),
                    "wildcard": tiers.get("wildcard", 0), "risks": len(risks), "inventory_total": verified_total},
        "executive": _executive(report, risks, sources, authorisation, who, lang),
        "risks": risks,
        "inventory": inventory,
        "limits": {
            "sources": sources,
            "disabled": dict(sorted((policy.get("disabled") or {}).items())),
            "deadline_hit": bool(coverage.get("deadline_hit")),
            "entity_cap": coverage.get("entity_cap"),
        },
        "method": {"ruleset": RULESET_VERSION, "packs": (report.get("packs") or {}).get("effective_sha256", "")[:16],
                   "sources_used": sorted(s["source"] for s in sources if s["outcome"] != "idle")},
        "evidence": {"cited": cited_rows, "cited_total": len(cited)},
        "polish": None,
    }


def evidence_problems(facts: dict, evidence_ids: set[str]) -> list[str]:
    """Statements about the client that cite nothing, or cite a record the bundle does not hold."""
    problems = []
    for index, sentence in enumerate(facts["executive"], 1):
        if sentence["kind"] == "fact" and not sentence["evidence_ids"]:
            problems.append(f"executive statement {index} cites no evidence")
        problems += [f"executive statement {index} cites {i[:12]}, not in the bundle" for i in sentence["evidence_ids"] if i not in evidence_ids]
    for row in facts["risks"]:
        if not row["evidence_ids"]:
            problems.append(f"{row['ref']} cites no evidence")
        problems += [f"{row['ref']} cites {i[:12]}, not in the bundle" for i in row["evidence_ids"] if i not in evidence_ids]
    for row in facts["inventory"]:
        if not row["evidence_ids"]:
            problems.append(f"inventory row {row['name']} cites no evidence")
    return problems
