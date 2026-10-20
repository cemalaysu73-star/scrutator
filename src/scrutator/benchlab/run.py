"""`scrutator bench`: OSINT-Bench v0, offline, one command.

Six sections, each a set of metrics with thresholds:

- risk_rules: the planted risk lab (every rule planted at least once) and a clean zone (no risk expected).
- attribution: the planted attribution lab, precision and recall by band.
- name_tiers: the tier lab, one zone with a wildcard and one without; every name must land in its expected tier.
- bundles: a signed bundle of the risk lab; verify with the signer pinned; nine tamper cases that must all fail;
  a replay against the unchanged lab that must find every replayable record unchanged.
- scope_safety: every DNS question and HTTP request of the three lab scans, against the scope (and, for the
  attribution lab, the candidates it selected): none may fall outside.
- hallucination: verify/grounding.py and the verifier against a writer that asserts unsupported things
  (see benchlab/halluc.py).

The JSON written has a stable shape (`schema: "scrutator-bench/1"`); the exit status is 1 if any threshold fails.
Nothing here touches the network, except `--verifier-model`, which asks a model server on this machine (loopback
only)."""

import base64
import hashlib
import ipaddress
import json
import re
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from scrutator import __version__
from scrutator.attribution import evaluate
from scrutator.benchlab import attrlab, halluc, risklab, tierlab
from scrutator.bundle.keys import fingerprint, generate_keypair, load_private_key, private_key_path, public_raw_from_private, sign
from scrutator.bundle.reader import read_raw
from scrutator.bundle.replay import replay_evidence, subject_names
from scrutator.bundle.verify import verify_bundle
from scrutator.bundle.writer import create_bundle
from scrutator.egress import SOURCE_HOSTS
from scrutator.model import Entity, EntityType
from scrutator.modules import rdap as rdap_module
from scrutator.modules.base import ModuleContext
from scrutator.modules.registry import load_builtin_modules
from scrutator.packs import load_packs
from scrutator.report import build_report, render_html, render_json
from scrutator.scan import run_scan
from scrutator.scope import ScopePolicy
from scrutator.store import Store

SCHEMA = "scrutator-bench/1"
SEED = Entity(type=EntityType.DOMAIN, value="example.com")
KEYLESS = {m.name for m in load_builtin_modules() if not m.needs_key}


def _metric(value: Any, threshold: str | None = None, ok: bool | None = None) -> dict:
    return {"value": value, "threshold": threshold, "pass": ok}


def _section(metrics: dict[str, dict], notes: list[str], started: float) -> dict:
    checked = [m["pass"] for m in metrics.values() if m["pass"] is not None]
    return {"pass": all(checked), "seconds": round(time.perf_counter() - started, 2), "metrics": metrics, "notes": notes}


async def _scan(work: Path, name: str, resolver, router, *, scope, modules, packs, **options):
    store = Store(work / name / "scrutator.db")
    async with httpx.AsyncClient(transport=router.transport()) as http:
        scan_id, stats = await run_scan(SEED, ScopePolicy(domains=list(scope)), store, ModuleContext(http=http, resolver=resolver),
                                        modules=modules, packs=packs, **options)
    return store, scan_id


# ------------------------------------------------------------------------------------------ sections


async def risk_rules(work: Path, state: dict) -> dict:
    started = time.perf_counter()
    modules = [m for m in load_builtin_modules() if m.name in KEYLESS]
    packs = load_packs([risklab.lab_packs_dir(work / "lab-packs")])
    resolver, router = risklab.lab_zone(), risklab.lab_router()
    store, scan_id = await _scan(work, "lab", resolver, router, scope=risklab.SCOPE_DOMAINS, modules=modules, packs=packs, max_steps=800)
    report = build_report(store, scan_id)
    (work / "lab" / "report.json").write_text(render_json(report), encoding="utf-8")
    (work / "lab" / "report.html").write_text(render_html(report), encoding="utf-8")
    found = {(r["rule_id"], r["entity_ids"][0]) for r in report["risks"]}
    detected = len(risklab.PLANTED & found)
    unsupported = sum(1 for r in report["risks"] if not r["evidence_ids"] or any(i not in report["evidence"] for i in r["evidence_ids"]))
    rules_seen = {r["rule_id"] for r in report["risks"]}
    clean_resolver, clean_router = risklab.clean_zone(), risklab.clean_router()
    clean_store, clean_id = await _scan(work, "clean", clean_resolver, clean_router, scope=["example.com"], modules=modules, packs=load_packs(), max_steps=800)
    clean = build_report(clean_store, clean_id)
    clean_store.close()
    state.update(lab=(store, scan_id, report, resolver, router), lab_scope=risklab.SCOPE_DOMAINS, clean=(clean_resolver, clean_router))
    metrics = {
        "planted_issues": _metric(len(risklab.PLANTED)),
        "planted_detected": _metric(detected, f"= {len(risklab.PLANTED)}", detected == len(risklab.PLANTED)),
        "rules_exercised": _metric(len(risklab.PLANTED_RULES & rules_seen), f"= {len(risklab.PLANTED_RULES)}", risklab.PLANTED_RULES <= rules_seen),
        "risks_without_evidence": _metric(unsupported, "= 0", unsupported == 0),
        "clean_zone_risks": _metric(len(clean["risks"]), "= 0", not clean["risks"]),
        "lab_findings": _metric(report["summary"]["findings"]),
        "lab_evidence_records": _metric(len(report["evidence"])),
    }
    missing = sorted(f"{r} on {e}" for r, e in risklab.PLANTED - found)
    return _section(metrics, [f"missed: {', '.join(missing)}"] if missing else [], started)


async def attribution(work: Path, state: dict) -> dict:
    started = time.perf_counter()
    log: list = []
    modules = [m for m in load_builtin_modules() if m.name in attrlab.MODULE_NAMES]
    resolver, router = attrlab.resolver(), attrlab.source_router(log)
    store, scan_id = await _scan(work, "attribution", resolver, router, scope=["example.com"], modules=modules,
                                 packs=attrlab.lab_packs(work / "attr-packs"), attribution=True, max_candidates=80)
    report = build_report(store, scan_id)
    result = evaluate(report["attribution"], attrlab.TRUTH)
    selected = {r["entity"].removeprefix("domain:") for r in store.audit_log(scan_id) if r["event"] == "candidate"}
    state.update(attribution=(store, scan_id, resolver, router, selected))
    probable = result["probable"]
    metrics = {
        "true_names": _metric(len(attrlab.TRUTH)),
        "candidates_listed": _metric(len(report["attribution"]["candidates"])),
        "probable_precision": _metric(probable["precision"], ">= 0.9", (probable["precision"] or 0) >= 0.9),
        "probable_or_better_precision": _metric(probable["or_better_precision"], ">= 0.9", (probable["or_better_precision"] or 0) >= 0.9),
    }
    for band, row in result.items():
        metrics[f"{band}_count"] = _metric(row["count"])
        metrics[f"{band}_precision"] = _metric(row["precision"])
        metrics[f"{band}_or_better_recall"] = _metric(row["or_better_recall"])
    notes = ["a synthetic lab written by the author of the scoring: a regression test of the design, not a real-world rate",
             "client.test is a planted false positive in the confirmed band that no DNS signal can remove; hidden.test cannot be found"]
    return _section(metrics, notes, started)


async def name_tiers(work: Path, state: dict) -> dict:
    started = time.perf_counter()
    modules = [m for m in load_builtin_modules() if m.name in tierlab.MODULE_NAMES]
    resolver, router = tierlab.resolver(), tierlab.source_router()
    got: dict[str, str] = {}
    evidence: dict[str, dict] = {}
    headlines = []
    for apex in tierlab.SCOPE_DOMAINS:  # one scan per zone, as a user would run them
        store = Store(work / "tiers" / f"{apex}.db")
        async with httpx.AsyncClient(transport=router.transport()) as http:
            scan_id, _ = await run_scan(Entity(type=EntityType.DOMAIN, value=apex), ScopePolicy(domains=[apex]), store,
                                        ModuleContext(http=http, resolver=resolver), modules=modules, packs=load_packs(), max_steps=500)
        report = build_report(store, scan_id)
        store.close()
        got |= {row["name"]: row["tier"] for row in report["names"]}
        evidence |= report["evidence"]
        headlines.append(f"{apex}: {report['summary']['headline']}")
    state.update(tiers=(resolver, router))
    wrong = {name: (got.get(name), want) for name, (want, _) in tierlab.EXPECTED.items() if got.get(name) != want}
    probes = [e for e in evidence.values() if e["source"] == "dns" and "wc-probe-" in e["request"]]
    wildcard_seen = any(e["request"].endswith(".example.net") and tierlab.WILDCARD_ADDRESS in e["payload"] for e in probes)
    no_false_wildcard = not any(e["request"].endswith(".example.com") and e["payload"] not in ("NXDOMAIN",) and "NXDOMAIN" not in e["payload"] for e in probes)
    correct = len(tierlab.EXPECTED) - len(wrong)
    metrics = {
        "names_with_expected_tier": _metric(len(tierlab.EXPECTED)),
        "tier_accuracy": _metric(round(correct / len(tierlab.EXPECTED), 4), "= 1.0", not wrong),
        "wildcard_detected": _metric(wildcard_seen, "= true", wildcard_seen),
        "no_wildcard_where_none": _metric(no_false_wildcard, "= true", no_false_wildcard),
        "headline": _metric("; ".join(headlines)),
    }
    notes = [f"{name}: got {g}, expected {w}" for name, (g, w) in sorted(wrong.items())]
    return _section(metrics, notes, started)


def _forge(src: Path, dst: Path, private, changes: dict) -> Path:
    """Change data files, rebuild the manifest hashes and sign it with `private`: a determined forger."""
    raw = read_raw(src).files
    files = {n: raw[n] for n in ("report.json", "evidence.jsonl", "audit.jsonl")}
    for name, change in changes.items():
        files[name] = change(files[name])
    manifest = json.loads(raw["manifest.json"])
    manifest["files"] = {n: {"sha256": hashlib.sha256(d).hexdigest(), "bytes": len(d)} for n, d in files.items()}
    public = public_raw_from_private(private)
    manifest["public_key"] = base64.b64encode(public).decode()
    manifest["key_fingerprint"] = fingerprint(public)
    body = json.dumps(manifest, sort_keys=True, indent=2).encode()
    with zipfile.ZipFile(dst, "w") as archive:
        for entry, data in {**files, "manifest.json": body, "manifest.sig": base64.b64encode(sign(private, body)) + b"\n"}.items():
            archive.writestr(entry, data)
    return dst


def _rewrite(src: Path, dst: Path, name: str, change) -> Path:
    files = read_raw(src).files
    files[name] = change(files[name])
    with zipfile.ZipFile(dst, "w") as archive:
        for entry, data in files.items():
            archive.writestr(entry, data)
    return dst


def _flip(data: bytes) -> bytes:
    middle = len(data) // 2
    return data[:middle] + bytes([data[middle] ^ 0x01]) + data[middle + 1 :]


def _rows(data: bytes) -> list[dict]:
    return [json.loads(line) for line in data.decode().splitlines() if line.strip()]


def _jsonl(rows: list[dict]) -> bytes:
    return ("\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n").encode()


async def bundles(work: Path, state: dict, key) -> dict:
    started = time.perf_counter()
    store, scan_id, report, resolver, router = state["lab"]
    path = work / "lab" / "proof.scrutator"
    create_bundle(store, scan_id, key, path)
    pin = fingerprint(public_raw_from_private(key))
    genuine = verify_bundle(path, pinned_fingerprint=pin)
    attacker = load_private_key(private_key_path(_attacker_keys(work)))
    tampered = work / "tampered"
    tampered.mkdir(exist_ok=True)

    def drop_evidence(data: bytes) -> bytes:
        rows = _rows(data)
        cited = {i for f in report["findings"] for i in f["evidence_ids"]}
        return _jsonl([r for r in rows if r["id"] != sorted(cited)[0]])

    def alter_payload(data: bytes) -> bytes:
        rows = _rows(data)
        rows[0]["payload"] = rows[0]["payload"] + " "
        return _jsonl(rows)

    def remove_risk(data: bytes) -> bytes:
        body = json.loads(data)
        body["risks"] = body["risks"][1:]
        return json.dumps(body, sort_keys=True, indent=2).encode()

    def raise_confidence(data: bytes) -> bytes:
        body = json.loads(data)
        for finding in body["findings"]:
            if finding["confidence"] == "low":
                finding["confidence"] = "high"
                break
        return json.dumps(body, sort_keys=True, indent=2).encode()

    def drop_audit_tail(data: bytes) -> bytes:
        return b"".join(data.splitlines(keepends=True)[:-1])

    cases = {
        "flip a byte of report.json": _rewrite(path, tampered / "1.scrutator", "report.json", _flip),
        "flip a byte of evidence.jsonl": _rewrite(path, tampered / "2.scrutator", "evidence.jsonl", _flip),
        "flip a byte of audit.jsonl": _rewrite(path, tampered / "3.scrutator", "audit.jsonl", _flip),
        "edit the manifest, keep the signature": _rewrite(path, tampered / "4.scrutator", "manifest.json", lambda d: d.replace(b'"format": 1', b'"format": 2')),
        "re-sign a changed report with another key": _forge(path, tampered / "5.scrutator", attacker, {"report.json": remove_risk}),
        "hide a risk, re-signed with the real key": _forge(path, tampered / "6.scrutator", key, {"report.json": remove_risk}),
        "raise a confidence, re-signed with the real key": _forge(path, tampered / "7.scrutator", key, {"report.json": raise_confidence}),
        "drop a cited evidence record, re-signed with the real key": _forge(path, tampered / "8.scrutator", key, {"evidence.jsonl": drop_evidence}),
        "alter an evidence payload, re-signed with the real key": _forge(path, tampered / "9.scrutator", key, {"evidence.jsonl": alter_payload}),
        "truncate the audit log, re-signed with another key": _forge(path, tampered / "10.scrutator", attacker, {"audit.jsonl": drop_audit_tail}),
    }
    caught = {}
    for label, case in cases.items():
        result = verify_bundle(case, pinned_fingerprint=pin)
        caught[label] = (not result.ok, ", ".join(c.name for c in result.checks if not c.ok))
    records = [json.loads(line) for line in read_raw(path).files["evidence.jsonl"].decode().splitlines() if line.strip()]
    async with httpx.AsyncClient(transport=router.transport()) as http:
        replayed = await replay_evidence(records, http, resolver, subject=subject_names(report))
    tally = {s: sum(1 for r in replayed if r.status == s) for s in ("unchanged", "changed", "unavailable", "skipped")}
    replayable = len(replayed) - tally["skipped"]
    detected = sum(1 for ok, _ in caught.values() if ok)
    metrics = {
        "genuine_bundle_verifies_pinned": _metric(genuine.ok, "= true", genuine.ok),
        "tamper_cases": _metric(len(cases)),
        "tamper_detected": _metric(detected, f"= {len(cases)}", detected == len(cases)),
        "replay_records": _metric(len(replayed)),
        "replay_unchanged_share": _metric(round(tally["unchanged"] / replayable, 4) if replayable else None, "= 1.0", replayable > 0 and tally["unchanged"] == replayable),
        "replay_skipped": _metric(tally["skipped"]),
        "bundle_bytes": _metric(path.stat().st_size),
    }
    notes = [f"{label}: {'caught by ' + checks if ok else 'NOT CAUGHT'}" for label, (ok, checks) in caught.items()]
    return _section(metrics, notes, started)


def _attacker_keys(work: Path) -> Path:
    target = work / "attacker-keys"
    if not private_key_path(target).exists():
        generate_keypair(target)
    return target


async def scope_safety(work: Path, state: dict) -> dict:
    started = time.perf_counter()
    violations: list[str] = []
    questions = requests = 0

    name_in = re.compile(r"(?<![\w.-])[a-z0-9_-]+(?:\.[a-z0-9_-]+)+(?![\w:])", re.IGNORECASE)  # not a field name such as page.domain:

    def subjects(request: httpx.Request) -> list[str]:
        """The names and addresses a request asks about: every host-like token in its query parameters, or the
        last path segment for the services that put it there (RDAP, InternetDB, passive DNS)."""
        found = []
        for key in ("q", "domain", "url", "query", "resource"):
            if key in request.url.params:
                value = re.sub(r"(^|[\s:])[%*]\.", r"", request.url.params[key])  # %.example.com, *.example.com
                found += name_in.findall(value)
        path = request.url.path
        if request.url.host in ("rdap.org", "internetdb.shodan.io") or path.startswith("/pdns/"):
            found.append(path.rstrip("/").rsplit("/", 1)[-1])
        return found

    def audit(label: str, resolver, router, scope: list[str], extra: set[str] = frozenset(), linked: set[str] = frozenset()):
        nonlocal questions, requests
        policy = ScopePolicy(domains=scope)
        allowed_names = set(extra) | {f"_dmarc.{n}" for n in extra}
        for name, _ in resolver.calls:
            questions += 1
            if not (policy.decide(name).allowed or name in allowed_names):
                violations.append(f"{label}: DNS question about {name}")
        for request in router.calls:
            requests += 1
            host = request.url.host
            if host not in SOURCE_HOSTS:
                violations.append(f"{label}: request to {host}")
                continue
            for about in subjects(request):
                try:
                    ipaddress.ip_address(about)
                except ValueError:
                    if not (policy.decide(about).allowed or about in allowed_names):
                        violations.append(f"{label}: {host} asked about {about}")
                    continue
                if about not in linked:
                    violations.append(f"{label}: lookup of address {about}, which no in-scope name resolves to")

    store, scan_id, report, resolver, router = state["lab"]
    audit("risk lab", resolver, router, risklab.SCOPE_DOMAINS, linked={e["value"] for e in report["entities"] if e["state"] == "linked"})
    clean_resolver, clean_router = state["clean"]
    audit("clean zone", clean_resolver, clean_router, ["example.com"], linked={"192.0.2.1", "192.0.2.10"})
    a_store, a_scan, a_resolver, a_router, selected = state["attribution"]
    a_linked = {s.entity.value for s in a_store.entities(a_scan) if s.state.value == "linked"}
    audit("attribution lab", a_resolver, a_router, ["example.com"], extra=selected, linked=a_linked)
    t_resolver, t_router = state["tiers"]
    audit("tier lab", t_resolver, t_router, tierlab.SCOPE_DOMAINS)
    third_party = sorted({name for name, _ in resolver.calls if name.endswith("example.org")})
    metrics = {
        "dns_questions": _metric(questions),
        "http_requests": _metric(requests),
        "out_of_scope_contacts": _metric(len(violations), "= 0", not violations),
        "third_party_names_queried": _metric(len(third_party), "= 0", not third_party),
        "candidates_looked_at": _metric(len(selected)),
    }
    return _section(metrics, violations[:20], started)


async def hallucination(work: Path, state: dict, model: str | None, ollama_url: str) -> dict:
    started = time.perf_counter()
    notes = []
    if model:
        from scrutator.ai.net import is_loopback
        from scrutator.ai.ollama import OllamaProvider

        if not is_loopback(ollama_url):
            raise ValueError("--ollama-url must be a loopback address: the bench never sends lab data off this machine")
        async with httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=5.0), follow_redirects=False) as client:
            results = await halluc.hallucination_test(lambda: OllamaProvider(client, model, ollama_url))
        notes.append(f"local model verifier: ollama {model} at {ollama_url}")
    else:
        results = await halluc.hallucination_test()
        notes.append("local model verifier: not run (pass --verifier-model to measure one)")
    notes.append("the gated row (floor + facts-only verifier) uses a mechanical stand-in judge, not a language model: it shows the "
                 "pipeline publishes nothing unsupported when the verifier does its job; the obedient row is the worst case")
    gate = results["floor + facts-only verifier"]
    metrics = {
        "statements": _metric(gate["unsupported_total"] + gate["supported_total"]),
        "unsupported_statements": _metric(gate["unsupported_total"]),
    }
    for name, row in results.items():
        key = name.replace(" + ", "_").replace(" ", "_").replace("-", "_")
        threshold = "= 0" if name == "floor + facts-only verifier" else None
        metrics[f"{key}__unsupported_published"] = _metric(row["unsupported_published"], threshold, row["unsupported_published"] == 0 if threshold else None)
        metrics[f"{key}__unsupported_survival"] = _metric(row["unsupported_survival"])
        metrics[f"{key}__supported_kept_share"] = _metric(row["supported_kept_share"], ">= 0.8" if threshold else None,
                                                          row["supported_kept_share"] >= 0.8 if threshold else None)
        if row["survivors"]:
            notes.append(f"{name}: survived: {', '.join(row['survivors'])}")
    state["hallucination_detail"] = results
    return _section(metrics, notes, started)


# ------------------------------------------------------------------------------------------ the whole run


async def run_bench(out: Path, *, key=None, model: str | None = None, ollama_url: str = "http://127.0.0.1:11434") -> dict:
    from scrutator.ai.net import is_loopback

    if model and not is_loopback(ollama_url):
        raise ValueError("--ollama-url must be a loopback address: the bench never sends lab data off this machine")
    out.mkdir(parents=True, exist_ok=True)
    for name in ("lab", "clean", "attribution", "tiers"):
        (out / name).mkdir(parents=True, exist_ok=True)
        for old_db in (out / name).glob("*.db"):
            old_db.unlink()
    if key is None:
        key_dir = out / "keys"
        if not private_key_path(key_dir).exists():
            generate_keypair(key_dir)
        key = load_private_key(private_key_path(key_dir))
    started = time.perf_counter()
    state: dict = {}
    # The lab answers instantly: rdap.org's real pacing (eight at once, then one a second) would only add waiting.
    paced = rdap_module.PACE
    rdap_module.PACE = (100_000, 100_000.0)
    try:
        sections = await _sections(out, state, key, model, ollama_url)
    finally:
        rdap_module.PACE = paced
    state["lab"][0].close()
    state["attribution"][0].close()
    result = {
        "schema": SCHEMA,
        "tool": {"name": "scrutator", "version": __version__},
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "pass": all(s["pass"] for s in sections.values()),
        "seconds": round(time.perf_counter() - started, 2),
        "signing_key": fingerprint(public_raw_from_private(key)),
        "sections": sections,
        "hallucination_detail": state.get("hallucination_detail", {}),
    }
    (out / "bench.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "bench.md").write_text(render_table(result) + "\n", encoding="utf-8")
    return result


async def _sections(out: Path, state: dict, key, model, ollama_url) -> dict:
    return {
        "risk_rules": await risk_rules(out, state),
        "attribution": await attribution(out, state),
        "name_tiers": await name_tiers(out, state),
        "bundles": await bundles(out, state, key),
        "scope_safety": await scope_safety(out, state),
        "hallucination": await hallucination(out, state, model, ollama_url),
    }


def render_table(result: dict) -> str:
    lines = [
        f"OSINT-Bench v0 (scrutator {result['tool']['version']}, {result['schema']}): {'PASS' if result['pass'] else 'FAIL'} in {result['seconds']} s",
        "",
        "| Section | Metric | Value | Threshold | Result |",
        "|---|---|---|---|---|",
    ]
    for section, body in result["sections"].items():
        for name, metric in body["metrics"].items():
            mark = "" if metric["pass"] is None else ("pass" if metric["pass"] else "FAIL")
            value = metric["value"]
            lines.append(f"| {section} | {name} | {value} | {metric['threshold'] or ''} | {mark} |")
    notes = [f"- {section}: {note}" for section, body in result["sections"].items() for note in body["notes"]]
    if notes:
        lines += ["", "Notes:", *notes]
    return "\n".join(lines)
