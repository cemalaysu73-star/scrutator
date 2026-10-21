"""Making an audit from a signed bundle, writing it, and checking one (`scrutator audit-check`)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from scrutator import __version__
from scrutator.audit.branding import Branding
from scrutator.audit.content import AuditError, authorisation_from_log, build_audit, evidence_problems
from scrutator.audit.pdf import print_pdf
from scrutator.audit.render import read_embedded, render_audit
from scrutator.bundle.reader import read_raw
from scrutator.bundle.verify import verify_bundle

AUDIT_LOG = "audit-log.jsonl"


@dataclass
class LoadedBundle:
    report: dict
    audit_records: list[dict]
    evidence_ids: set[str]
    payloads: dict[str, str]
    info: dict


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def load_bundle(path: Path, *, pin: str | None = None) -> LoadedBundle:
    """A bundle that passes every check of `scrutator verify` (pinned when `pin` is given), read for an audit."""
    checked = verify_bundle(path, pinned_fingerprint=pin)
    if not checked.ok:
        failing = next(c for c in checked.checks if not c.ok)
        raise AuditError(f"{path.name} fails verification ({failing.name}: {failing.detail}); an audit is never made from it")
    files = read_raw(path).files
    report = json.loads(files["report.json"])
    audit_records = [json.loads(json.loads(line)["record"]) for line in files["audit.jsonl"].decode("utf-8").splitlines() if line.strip()]
    payloads = {}
    for line in files["evidence.jsonl"].decode("utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            payloads[row["id"]] = row["payload"]
    info = {"file": "proof.scrutator", "sha256": file_sha256(path), "key_fingerprint": checked.key_fingerprint, "records": len(payloads)}
    return LoadedBundle(report, audit_records, set(payloads), payloads, info)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ------------------------------------------------------------------------------------------- AI rewording


def _sentence_facts(facts: dict, index: int) -> list[str]:
    sentence = facts["executive"][index]
    by_ref = {r["ref"]: r for r in facts["risks"]}
    claims = [sentence["text"]]
    for ref in sentence["risk_refs"][:6]:
        risk = by_ref.get(ref)
        if risk is not None:
            claims.append(f"{risk['title']}. {risk['explanation']}")
    return claims


async def polish_facts(ai, facts: dict, payloads: dict[str, str]) -> dict | None:
    """Offer each executive `fact` sentence of an English audit to the writer model; keep verified rewordings."""
    from scrutator.verify.polish import polish_sentence

    if ai is None or facts["lang"] != "en":
        return None
    statements = []
    for index, sentence in enumerate(facts["executive"]):
        if sentence["kind"] != "fact":
            continue
        cited = [payloads[i] for i in sentence["evidence_ids"][:20] if i in payloads]
        result = await polish_sentence(ai, sentence["text"], _sentence_facts(facts, index), cited)
        statements.append({"index": index, "original": sentence["text"], "text": result.text, "offered": result.offered, "verdict": result.verdict})
    described = ai.describe()["providers"] if hasattr(ai, "describe") else {}
    return {"models": {role: f"{p.get('provider')}/{p.get('model')}" for role, p in described.items()}, "statements": statements}


# ------------------------------------------------------------------------------------------- writing


@dataclass
class Written:
    html: Path
    facts: Path
    pdf: Path | None
    pdf_problem: str
    files: list[str] = field(default_factory=list)


def write_audit(out: Path, facts: dict, brand: Branding, *, pdf: bool = True, browser: str | None = None) -> Written:
    out.mkdir(parents=True, exist_ok=True)
    html_path = out / "audit.html"
    html_path.write_text(render_audit(facts, brand), encoding="utf-8", newline="\n")
    facts_path = out / "audit.json"
    facts_path.write_text(json.dumps(facts, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    pdf_path, problem = None, "not asked for (--no-pdf)"
    if pdf:
        target = out / "audit.pdf"
        problem = print_pdf(html_path, target, browser=browser)
        pdf_path = target if not problem else None
    return Written(html_path, facts_path, pdf_path, problem, [p.name for p in (html_path, facts_path, pdf_path) if p is not None])


def append_log(out: Path, record: dict) -> None:
    """A line in the deliverable folder's own log (for audits made from an existing bundle, whose signed log cannot
    be changed): what was made from which bundle, under which authorisation hash."""
    with (out / AUDIT_LOG).open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


# ------------------------------------------------------------------------------------------- checking


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


def check_audit(page_path: Path, bundle_path: Path, *, pin: str | None = None) -> list[Check]:
    """Re-derive an audit from its bundle and compare: the bundle verifies, it is the bundle the page names, every
    number, finding and sentence follows from it, every cited record is in it, AI rewordings pass the deterministic
    floor, and the page is byte for byte what those facts and that branding render to."""
    from scrutator.audit.branding import Branding as _Branding
    from scrutator.verify.polish import floor_problem

    checks: list[Check] = []
    add = lambda name, ok, detail="": checks.append(Check(name, ok, detail))  # noqa: E731
    try:
        loaded = load_bundle(bundle_path, pin=pin)
        add("bundle verifies" + (" (pinned)" if pin else ""), True)
    except AuditError as exc:
        add("bundle verifies", False, str(exc))
        return checks
    try:
        page = page_path.read_text(encoding="utf-8")
        embedded = read_embedded(page)
        facts, brand = embedded["facts"], _Branding.from_dict(embedded["branding"])
        add("audit data readable", True)
    except Exception as exc:  # noqa: BLE001 - the page is untrusted input
        add("audit data readable", False, f"{type(exc).__name__}: {exc}")
        return checks

    same_bundle = facts.get("bundle", {}).get("sha256") == loaded.info["sha256"] and facts["bundle"].get("key_fingerprint") == loaded.info["key_fingerprint"]
    add("names this bundle", same_bundle, "" if same_bundle else "the page names another bundle (sha256 or signing key differ)")

    auth = facts.get("authorisation") or {}
    signed = authorisation_from_log(loaded.audit_records)
    if auth.get("recorded") == "signed":
        ok = signed == auth
        add("authorisation in the signed log", ok, "" if ok else "the page's authorisation is not the one the bundle's audit log records")
    else:
        add("authorisation recorded at report time", True, "not in the signed log: the scan predates it")
    try:
        rebuilt = build_audit(
            loaded.report, authorisation=auth, bundle=loaded.info, lang=facts["lang"], auditor=facts["who"]["auditor"],
            client=facts["who"]["client"], generated_at=facts["generated_at"],
        )
        rebuilt["polish"] = facts.get("polish")
        made_with, rebuilt["tool"] = facts.get("tool"), facts.get("tool")  # which version made it is information, not content
        same = rebuilt == facts
        why = "a number, finding or sentence is not what the bundle implies"
        if not same and made_with != __version__:
            why += f" (made with scrutator {made_with}, checked with {__version__}: check with the version that made it)"
        add("content derivable", same, "" if same else why)
    except (AuditError, KeyError, TypeError, ValueError) as exc:
        add("content derivable", False, f"{type(exc).__name__}: {exc}")
        return checks
    problems = evidence_problems(facts, loaded.evidence_ids)
    add("every claim cites evidence in the bundle", not problems, "; ".join(problems[:3]))
    bad = []
    for item in (facts.get("polish") or {}).get("statements", []):
        if item.get("verdict") == "verified":
            index = item["index"]
            cited = [loaded.payloads[i] for i in facts["executive"][index]["evidence_ids"][:20] if i in loaded.payloads]
            problem = floor_problem(item["text"], _sentence_facts(facts, index), cited)
            if problem or item.get("original") != facts["executive"][index]["text"]:
                bad.append(f"statement {index + 1}: {problem or 'original wording differs'}")
    add("AI rewordings pass the deterministic floor", not bad, "; ".join(bad[:3]))
    same_page = render_audit(facts, brand) == page
    add("page is what the facts render to", same_page, "" if same_page else "the visible page was edited after it was made")
    return checks
