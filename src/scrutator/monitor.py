"""Monitoring that tells a client (or a bug-bounty hunter) only what is new: snapshots, alerts, dedupe and digests.

A snapshot is what a report says about the things worth an alert, restricted to a scope: the verified names, the
risks (takeover candidates among them), the certificates that name an in-scope host, and the open services Shodan's
InternetDB lists on the addresses those names resolve to. Two snapshots give the alerts; an alert's key is remembered
in the state file so the same thing is announced once, and announced again only after it went away and came back.

Every alert carries the evidence ids of the records it rests on and a deterministic "why this matters" sentence. A
model may reword that sentence (scrutator.verify.polish): the rewording is kept only when the deterministic floor and
the verifier pass it, otherwise the deterministic sentence stays. No alert is ever based on an active probe.
"""

from __future__ import annotations

import json
import os
import smtplib
import ssl
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

SEVERITIES = ("info", "low", "medium", "high")
_RANK = {s: i for i, s in enumerate(SEVERITIES)}
STATE_FILE = "monitor-state.json"
MAX_STATE_BYTES = 64 * 1024 * 1024
TAKEOVER_RULES = ("dangling-cname-claimable", "dangling-cname-known-service", "dangling-cname")
CERT_SOURCES = ("crtsh", "certspotter")

WHY = {
    "new_name": "A name that newly resolves is new attack surface: confirm it is yours, needed and maintained.",
    "gone_name": "A name that stopped resolving may leave references behind (links, certificates, aliases) that someone could claim.",
    "new_risk": "A new finding of this kind was not there at the last check: it appeared since then.",
    "resolved_risk": "A finding from an earlier check is no longer there: it was fixed or the name was removed.",
    "new_takeover": "An alias that points at a resource that no longer exists can be taken over by whoever registers that resource.",
    "new_cert": "A new certificate names a host under the domain: new services usually appear in certificate logs first.",
    "new_service": "A newly listed open port is a newly reachable service on an address one of the names resolves to.",
}
WHY_TR = {
    "new_name": "Yeni çözümlenen bir ad yeni saldırı yüzeyidir: sizin olduğunu, gerekli ve bakımlı olduğunu doğrulayın.",
    "gone_name": "Çözümlenmeyi bırakan bir ad, başkasının sahiplenebileceği izler (bağlantılar, sertifikalar, takma adlar) bırakabilir.",
    "new_risk": "Bu türden bir bulgu son denetimde yoktu: o zamandan beri ortaya çıktı.",
    "resolved_risk": "Önceki bir denetimdeki bulgu artık yok: düzeltildi ya da ad kaldırıldı.",
    "new_takeover": "Artık var olmayan bir kaynağa işaret eden takma ad, o kaynağı kaydeden kişi tarafından ele geçirilebilir.",
    "new_cert": "Yeni bir sertifika alan adı altındaki bir ana makineyi anıyor: yeni servisler genellikle önce sertifika kayıtlarında görünür.",
    "new_service": "Yeni listelenen açık bir port, adlardan birinin çözümlendiği adreste yeni erişilebilir bir servistir.",
}


# ------------------------------------------------------------------------------------------- snapshot


def _payload_rows(payload: str):
    try:
        rows = json.loads(payload)
    except (TypeError, ValueError):
        return []
    return rows if isinstance(rows, list) else []


def snapshot(report: dict, in_scope: Callable[[str], bool]) -> dict:
    """What a report says about the things worth an alert, inside `in_scope` (a predicate on host names)."""
    names = {r["name"]: sorted(r["evidence_ids"]) for r in report.get("names") or [] if r.get("tier") == "verified" and in_scope(r["name"])}
    risks = {}
    for risk in report.get("risks") or []:
        hosts = [e.split(":", 1)[1] for e in risk["entity_ids"] if e.startswith("domain:")]
        if hosts and not in_scope(hosts[0]):
            continue
        risks[risk["fingerprint"]] = {"rule_id": risk["rule_id"], "severity": risk["severity"], "title": risk["title"],
                                      "entities": [e.split(":", 1)[-1] for e in risk["entity_ids"]], "explanation": risk["explanation"],
                                      "evidence_ids": sorted(risk["evidence_ids"])}
    certs: dict[str, dict] = {}
    for evidence_id, record in sorted((report.get("evidence") or {}).items()):
        if not isinstance(record, dict) or record.get("source") not in CERT_SOURCES:
            continue
        for row in _payload_rows(record.get("payload", "")):
            if not isinstance(row, dict) or row.get("id") is None:
                continue
            raw = row.get("name_value") if record["source"] == "crtsh" else "\n".join(str(n) for n in row.get("dns_names") or [])
            hosts = sorted({str(h).strip().lower().removeprefix("*.") for h in str(raw or "").splitlines() if h.strip()})
            hosts = [h for h in hosts if in_scope(h)]
            if not hosts:
                continue
            key = f"{record['source']}:{row['id']}"
            entry = certs.setdefault(key, {"names": [], "not_before": str(row.get("not_before") or ""), "evidence_ids": []})
            entry["names"] = sorted(set(entry["names"]) | set(hosts))[:20]
            if evidence_id not in entry["evidence_ids"]:
                entry["evidence_ids"].append(evidence_id)
    addresses: dict[str, list[str]] = {}
    for row in report.get("names") or []:
        if row.get("tier") == "verified" and in_scope(row["name"]):
            for address in row.get("addresses") or []:
                addresses.setdefault(address, []).append(row["name"])
    services = {}
    for row in report.get("exposure") or []:
        if row.get("ip") not in addresses:
            continue
        for port in row.get("ports") or []:
            services[f"{row['ip']}:{port}"] = {"ip": row["ip"], "port": port, "names": sorted(addresses[row["ip"]])[:10],
                                               "evidence_ids": sorted(row["evidence_ids"])}
    return {"names": names, "risks": risks, "certs": certs, "services": services}


# ------------------------------------------------------------------------------------------- alerts


@dataclass
class Alert:
    kind: str
    key: str
    severity: str
    title: str
    detail: str
    evidence_ids: list[str]
    why: str
    why_source: str = "deterministic"  # or "ai-verified"
    entities: list[str] = field(default_factory=list)
    rule_id: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _why(kind: str, lang: str) -> str:
    return (WHY_TR if lang == "tr" else WHY)[kind]


def diff_snapshots(old: dict | None, new: dict, *, lang: str = "en", kinds: tuple[str, ...] | None = None) -> list[Alert]:
    """The alerts between two snapshots (none against no previous snapshot: the first run is the baseline)."""
    if old is None:
        return []
    alerts: list[Alert] = []
    for name in sorted(new["names"].keys() - old["names"].keys()):
        alerts.append(Alert("new_name", f"name:{name}", "low", f"New verified name: {name}", f"{name} resolves in public DNS (or a recent certificate names it).",
                            new["names"][name], _why("new_name", lang), entities=[name]))
    for name in sorted(old["names"].keys() - new["names"].keys()):
        alerts.append(Alert("gone_name", f"gone:{name}", "info", f"Name no longer verified: {name}", f"{name} was verified at the last check and is not now.",
                            old["names"][name], _why("gone_name", lang), entities=[name]))
    for fp in sorted(new["risks"].keys() - old["risks"].keys()):
        risk = new["risks"][fp]
        kind = "new_takeover" if risk["rule_id"] in TAKEOVER_RULES else "new_risk"
        alerts.append(Alert(kind, f"risk:{fp}", risk["severity"], f"{risk['title']} ({', '.join(risk['entities'][:2])})", risk["explanation"],
                            risk["evidence_ids"], _why(kind, lang), entities=risk["entities"], rule_id=risk["rule_id"]))
    for fp in sorted(old["risks"].keys() - new["risks"].keys()):
        risk = old["risks"][fp]
        alerts.append(Alert("resolved_risk", f"resolved:{fp}", "info", f"Resolved: {risk['title']} ({', '.join(risk['entities'][:2])})",
                            "The finding is not in the latest check.", risk["evidence_ids"], _why("resolved_risk", lang),
                            entities=risk["entities"], rule_id=risk["rule_id"]))
    for key in sorted(new["certs"].keys() - old["certs"].keys()):
        cert = new["certs"][key]
        alerts.append(Alert("new_cert", f"cert:{key}", "info", f"New certificate {key} for {', '.join(cert['names'][:3])}",
                            f"Certificate {key} (valid from {cert['not_before'] or 'unknown'}) names {', '.join(cert['names'][:5])}.",
                            cert["evidence_ids"], _why("new_cert", lang), entities=cert["names"]))
    for key in sorted(new["services"].keys() - old["services"].keys()):
        svc = new["services"][key]
        alerts.append(Alert("new_service", f"svc:{key}", "medium", f"New open port {svc['port']} on {svc['ip']}",
                            f"Shodan InternetDB lists port {svc['port']} open on {svc['ip']}, which {', '.join(svc['names'][:3])} resolve(s) to.",
                            svc["evidence_ids"], _why("new_service", lang), entities=[svc["ip"], *svc["names"]]))
    if kinds is not None:
        alerts = [a for a in alerts if a.kind in kinds]
    return sorted(alerts, key=lambda a: (-_RANK[a.severity], a.kind, a.key))


def dedupe(alerts: list[Alert], alerted: set[str], current_keys: set[str]) -> tuple[list[Alert], set[str]]:
    """Alerts not announced before; the set of keys to remember. A key is forgotten once its item is gone, so a thing
    that disappears and comes back is announced again."""
    fresh = [a for a in alerts if a.key not in alerted]

    def keep(key: str) -> bool:
        kind, _, rest = key.partition(":")
        if kind == "resolved":
            return f"risk:{rest}" not in current_keys  # remembered while the finding stays away
        if kind == "gone":
            return f"name:{rest}" not in current_keys
        return key in current_keys  # remembered while the thing is there

    return fresh, {k for k in alerted | {a.key for a in fresh} if keep(k)}


def current_keys(snap: dict) -> set[str]:
    return ({f"name:{n}" for n in snap["names"]} | {f"risk:{f}" for f in snap["risks"]} | {f"cert:{c}" for c in snap["certs"]}
            | {f"svc:{s}" for s in snap["services"]})


def at_least(alerts: list[Alert], minimum: str) -> list[Alert]:
    return [a for a in alerts if _RANK[a.severity] >= _RANK[minimum]]


# ------------------------------------------------------------------------------------------- AI "why this matters"


async def explain(ai, alerts: list[Alert], payloads: dict[str, str]) -> None:
    """Offer each alert's "why this matters" sentence to a writer model (English only); keep a rewording only when the
    deterministic floor and the verifier pass it against the alert's own facts."""
    from scrutator.verify.polish import polish_sentence

    if ai is None:
        return
    for alert in alerts:
        facts = [alert.why, f"{alert.title}. {alert.detail}"]
        cited = [payloads[i] for i in alert.evidence_ids[:10] if i in payloads]
        result = await polish_sentence(ai, alert.why, facts, cited)
        if result.verdict == "verified":
            alert.why, alert.why_source = result.text, "ai-verified"


# ------------------------------------------------------------------------------------------- state and digests


def load_state(directory: Path) -> dict:
    path = directory / STATE_FILE
    if not path.exists():
        return {"snapshot": None, "alerted": [], "runs": []}
    if path.stat().st_size > MAX_STATE_BYTES:
        raise ValueError(f"{path} is larger than {MAX_STATE_BYTES // 2**20} MiB")
    state = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(state, dict) or "alerted" not in state:
        raise ValueError(f"{path} is not a monitor state file")
    return state


def save_state(directory: Path, state: dict) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / STATE_FILE
    temp = target.with_suffix(".tmp")
    temp.write_text(json.dumps(state, indent=1, sort_keys=True), encoding="utf-8", newline="\n")
    os.replace(temp, target)


def week_of(moment: datetime) -> str:
    year, week, _ = moment.isocalendar()
    return f"{year}-W{week:02d}"


def render_digest(client: str, alerts: list[dict], *, period: str, lang: str = "en") -> str:
    """A Markdown digest of the alerts of a period, most severe first, each with its evidence ids."""
    title = "Haftalık izleme özeti" if lang == "tr" else "Weekly monitoring digest"
    lines = [f"# {title}: {client}", "", f"{'Dönem' if lang == 'tr' else 'Period'}: {period}", ""]
    if not alerts:
        lines.append("Bu dönemde yeni bir şey yok." if lang == "tr" else "Nothing new this period.")
        return "\n".join(lines) + "\n"
    counts = {s: sum(1 for a in alerts if a["severity"] == s) for s in reversed(SEVERITIES)}
    lines.append(", ".join(f"{n} {s}" for s, n in counts.items() if n))
    lines.append("")
    for severity in reversed(SEVERITIES):
        group = [a for a in alerts if a["severity"] == severity]
        if not group:
            continue
        lines.append(f"## {severity.upper()} ({len(group)})")
        lines.append("")
        for alert in group:
            lines.append(f"- **{alert['title']}** ({alert.get('at', '')[:10]})")
            lines.append(f"  {alert['detail']}")
            lines.append(f"  {'Neden önemli' if lang == 'tr' else 'Why this matters'}: {alert['why']}" + (" (AI, verified)" if alert.get("why_source") == "ai-verified" else ""))
            lines.append(f"  Evidence: {', '.join(i[:12] for i in alert['evidence_ids'][:6])}")
        lines.append("")
    return "\n".join(lines) + "\n"


def write_digest(directory: Path, client: str, history: list[dict], *, now: datetime | None = None, lang: str = "en") -> Path:
    """digest-<ISO week>.md: every alert of this week so far (rewritten each run, so it is complete at the week's end)."""
    moment = now or datetime.now(timezone.utc)
    week = week_of(moment)
    alerts = [a for a in history if week_of(datetime.fromisoformat(a["at"])) == week]
    target = directory / f"digest-{week}.md"
    target.write_text(render_digest(client, alerts, period=week, lang=lang), encoding="utf-8", newline="\n")
    return target


# ------------------------------------------------------------------------------------------- e-mail

SMTP_VARIABLES = ("SCRUTATOR_SMTP_HOST", "SCRUTATOR_SMTP_PORT", "SCRUTATOR_SMTP_USER", "SCRUTATOR_SMTP_PASSWORD", "SCRUTATOR_SMTP_FROM")


@dataclass(frozen=True)
class SmtpConfig:
    host: str
    port: int
    user: str
    password: str = field(repr=False)
    sender: str
    tls: str  # "starttls" or "ssl"

    @classmethod
    def from_env(cls, env=None) -> "SmtpConfig":
        """From SCRUTATOR_SMTP_* variables only: credentials never come from the command line, and are never logged."""
        env = os.environ if env is None else env
        missing = [v for v in ("SCRUTATOR_SMTP_HOST", "SCRUTATOR_SMTP_FROM") if not env.get(v)]
        if missing:
            raise ValueError(f"e-mail needs {', '.join(missing)} in the environment")
        port = int(env.get("SCRUTATOR_SMTP_PORT") or 587)
        return cls(env["SCRUTATOR_SMTP_HOST"], port, env.get("SCRUTATOR_SMTP_USER", ""), env.get("SCRUTATOR_SMTP_PASSWORD", ""),
                   env["SCRUTATOR_SMTP_FROM"], "ssl" if port == 465 else "starttls")


def send_email(config: SmtpConfig, recipients: list[str], subject: str, body: str, *, smtp_factory=None) -> str:
    """Send the digest. Returns "" or a one-line reason it was not sent, with no credential in it. Always TLS: STARTTLS
    (port 587, the default) or implicit TLS (465); a server that does not offer STARTTLS is refused."""
    message = EmailMessage()
    message["From"], message["To"], message["Subject"] = config.sender, ", ".join(recipients), subject
    message.set_content(body)
    context = ssl.create_default_context()
    try:
        if smtp_factory is not None:
            client = smtp_factory(config)
        elif config.tls == "ssl":
            client = smtplib.SMTP_SSL(config.host, config.port, context=context, timeout=30)
        else:
            client = smtplib.SMTP(config.host, config.port, timeout=30)
        with client:
            if config.tls == "starttls":
                client.starttls(context=context)
            if config.user:
                client.login(config.user, config.password)
            client.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        text = f"{type(exc).__name__}: {exc}"
        if config.password:
            text = text.replace(config.password, "[redacted]")
        return f"e-mail not sent ({text[:200]})"
    return ""
