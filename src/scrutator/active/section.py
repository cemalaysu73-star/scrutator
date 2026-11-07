"""The `active` section of a report and the checks `verify` makes on it.

`active_section(report)` is a pure function of the report's evidence (like the exposure table): the plan as it was recorded,
and what each check found. `verify` recomputes it and compares, so a section that does not follow from the evidence fails.

`active_problems(...)` is the guardrail audit of a bundle: it checks, from the signed audit log and the evidence alone, that
active checks were authorised before anything was sent, stayed inside the plan this tool derives from the passive evidence,
never went to a refused or shared-platform address, and did not exceed the recorded connection cap.
"""

from __future__ import annotations

from scrutator.active import DEFAULT_PORTS, PROBE_SOURCES
from scrutator.active.guard import RELAXABLE, Limits, refusal
from scrutator.active.plan import plan_active
from scrutator.active.records import active_records

WIDEST = Limits(max_connections=500, tcp_share=1.0)  # the widest plan the limits allow: the ceiling a bundle is held to (names per address from the record)


def active_section(report: dict) -> dict | None:
    found = active_records(report)
    if not found.any:
        return None

    def row(key: tuple, rec, **extra) -> dict:
        return {**extra, **rec.payload, "evidence_id": rec.evidence_id, "checked_at": rec.collected_at}

    plan = None
    if found.plan:
        rec = found.plan[-1]
        data = rec.payload
        plan = {
            "evidence_id": rec.evidence_id,
            "limits": data.get("limits"),
            "targets": [{"ip": t.get("ip"), "names": t.get("names"), "ports": [p.get("port") for p in t.get("ports") or [] if isinstance(p, dict)]}
                        for t in data.get("targets") or [] if isinstance(t, dict)],
            "skipped": [{k: s.get(k) for k in ("ip", "names", "kind", "reason", "platform", "signal", "verified")} for s in data.get("skipped") or [] if isinstance(s, dict)],
            "not_planned_for_the_cap": len(data.get("over_cap") or []),
        }
    return {
        "plan": plan,
        "checks": [row(k, r, ip=k[0], port=k[1]) for k, r in sorted(found.tcp.items())],
        "tls": [row(k, r, ip=k[0], port=k[1], sni=k[2]) for k, r in sorted(found.tls.items())],
        "legacy": [row(k, r, ip=k[0], port=k[1], version=k[2]) for k, r in sorted(found.legacy.items())],
        "http": [row(k, r, ip=k[0], port=k[1], name=k[2], scheme=k[3]) for k, r in sorted(found.http.items())],
    }


def authorisation_index(audit_records: list[dict]) -> tuple[int | None, dict | None]:
    """(index, record) of `active_confirmation_authorised` in the audit log, if any."""
    for index, record in enumerate(audit_records):
        if record.get("event") == "active_confirmation_authorised":
            return index, record
    return None, None


def active_problems(report: dict, audit_records: list[dict], evidence_rows: list[dict], packs, warnings: list[str]) -> str:
    """Why the bundle's active checks are not what was authorised and planned, or an empty string."""
    found = active_records(report)
    probe_rows = [r for r in evidence_rows if r.get("source") in PROBE_SOURCES]
    if not found.any and not probe_rows and not any(r.get("event", "").startswith("active_") for r in audit_records):
        return ""
    index, authorised = authorisation_index(audit_records)
    if authorised is None:
        return "the bundle holds active-probe evidence but its signed audit log records no active authorisation"
    first_lookup = next((i for i, r in enumerate(audit_records) if r.get("module")), len(audit_records))
    if index > first_lookup:
        return "active confirmation was authorised only after the first lookup"
    covered = next(
        (r for r in audit_records[:index] if (r.get("event") == "engagement" and r.get("active_testing") is True)
         or (r.get("event") == "self_attestation" and r.get("active") is True)),
        None,
    )
    if covered is None:
        return "the signed audit log records no authorisation that covers active testing before active confirmation began"
    relax = frozenset(authorised.get("test_mode") or ()) & RELAXABLE
    http_port, https_port, tls_ports = DEFAULT_PORTS["http"], DEFAULT_PORTS["https"], tuple(DEFAULT_PORTS["tls"])
    test_ports = authorised.get("test_ports")
    if relax and isinstance(test_ports, dict):  # only a run in test mode may have used other web ports
        try:
            http_port, https_port, tls_ports = int(test_ports["http"]), int(test_ports["https"]), tuple(int(p) for p in test_ports["tls"])
        except (KeyError, TypeError, ValueError):
            return "the recorded test ports are malformed"
    if relax:
        warnings.append(f"the bundle was made in test mode ({', '.join(sorted(relax))} addresses allowed); a real audit never is.")
    probes = [i for i, r in enumerate(audit_records) if r.get("module") in PROBE_SOURCES]
    plans = [i for i, r in enumerate(audit_records) if r.get("event") == "active_plan"]
    if probe_rows and not found.plan:
        return "the bundle holds probe evidence but no recorded plan"
    if probes and (not plans or plans[0] > probes[0]):
        return "a probe was logged before the plan was recorded"
    if found.plan and plans and audit_records[plans[0]].get("evidence_id") != found.plan[-1].evidence_id:
        return "the audit log's plan record is not the plan evidence the report holds"

    cap = (authorised.get("limits") or {}).get("max_connections")
    if not isinstance(cap, int) or isinstance(cap, bool) or cap < 1:
        return "the recorded authorisation has no connection cap"
    count = len(probe_rows)
    if count > cap:
        return f"{count} probe records exceed the recorded cap of {cap} connections"

    per_ip = (authorised.get("limits") or {}).get("max_names_per_ip")
    per_ip = per_ip if isinstance(per_ip, int) and not isinstance(per_ip, bool) and 1 <= per_ip <= 20 else WIDEST.max_names_per_ip
    ceiling = plan_active(report, packs, Limits(max_connections=500, tcp_share=1.0, max_names_per_ip=per_ip), relax)
    allowed = ceiling.allowed()
    names = {t["ip"]: set(t["probe_names"]) for t in ceiling.targets}
    for ip in sorted({k[0] for k in found.tcp} | {k[0] for k in found.tls} | {k[0] for k in found.legacy} | {k[0] for k in found.http}):
        bad = refusal(ip, relax)
        if bad:
            return f"{ip} was probed although it is refused ({bad})"
        if ip not in allowed:
            skipped = next((s for s in ceiling.skipped if s["ip"] == ip), None)
            why = f"it is skipped: {skipped['reason']}" if skipped else "no in-scope name resolves to it"
            return f"{ip} was probed outside the plan ({why})"
    for (ip, port) in found.tcp:
        if port not in allowed[ip]:
            return f"{ip}:{port} was probed although it is in neither the passive port list nor the fixed list"
    opened = {(ip, port) for (ip, port), rec in found.tcp.items() if rec.payload.get("state") == "open"}
    for (ip, port, sni) in found.tls:
        if (ip, port) not in opened or port not in tls_ports or (sni and sni not in names[ip]):
            return f"a TLS handshake with {ip}:{port} was made without an open TLS port or for a name that does not resolve there"
    for (ip, port, _version) in found.legacy:
        if (ip, port) not in opened or port not in tls_ports:
            return f"a legacy-protocol attempt on {ip}:{port} was made without an open TLS port"
    for (ip, port, name, scheme) in found.http:
        if (ip, port) not in opened or port != (https_port if scheme == "https" else http_port) or name not in names[ip]:
            return f"an HTTP request to {ip}:{port} for {name} was made outside ports 80/443, without an open port, or for a name that does not resolve there"
    # the audit log accounts for every probe record, under the module that made it
    logged: dict[str, str] = {}
    for record in audit_records:
        if record.get("event") == "ok" and record.get("module") in PROBE_SOURCES:
            for evidence_id in record.get("evidence_ids") or []:
                logged[evidence_id] = record["module"]
    for row in probe_rows:
        if logged.get(row["id"]) != row["source"]:
            return f"probe record {row['id'][:12]} is not accounted for in the signed audit log"
    return ""
