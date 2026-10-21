"""R7 bench sections, offline: `audit` (the client deliverable), `bounty` (scope import and new-asset detection) and
`monitor` (diff, dedupe, severity)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from scrutator.audit.branding import Branding
from scrutator.audit.content import authorisation_late, build_audit, evidence_problems
from scrutator.audit.make import check_audit, load_bundle, now, write_audit
from scrutator.audit.render import read_embedded, render_audit
from scrutator.bounty import BountyScope, parse_scope, parse_target
from scrutator.bundle.writer import create_bundle
from scrutator.monitor import at_least, current_keys, dedupe, diff_snapshots, render_digest, snapshot

HOSTILE_TEXT = '</style></script><script>alert(1)</script>"><img src=x onerror=alert(2)>'
HOSTILE_SCOPE = [
    "*", "*.*", "*.com", "*.com.tr", "*.co.uk", "example.*", "api.*.example.com", "*example.com", "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>", "file:///etc/passwd", "ftp://example.com", "https://example.com@evil.example/",
    "http://user:pw@example.com", "10.0.0.0/8", "192.168.1.1", "1.0.0.0/4", "exam​ple.com", "ex‮ample.com",
    "com.tr", "localhost", "not a host!",
]
SAFE_SCOPE = {"*.example.com": ("wildcard", "example.com"), "https://www.example.com/app?x=1": ("host", "www.example.com"),
              "example。com": ("host", "example.com"), "1.1.1.0/24": ("cidr", "1.1.1.0/24"), "example.com:8443": ("host", "example.com")}


def _metric(value, threshold=None, ok=None) -> dict:
    return {"value": value, "threshold": threshold, "pass": ok}


# ------------------------------------------------------------------------------------------- audit


def audit_metrics(work: Path, store, scan_id: int, key) -> tuple[dict, list[str]]:
    folder = work / "audit"
    shutil.rmtree(folder, ignore_errors=True)
    folder.mkdir(parents=True)
    bundle = folder / "proof.scrutator"
    create_bundle(store, scan_id, key, bundle)
    loaded = load_bundle(bundle)
    report = loaded.report
    domains = list((report.get("scope") or {}).get("domains") or [report["scan"]["seed"]])
    auth = authorisation_late(domains=domains, organisation="Lab Org (fixture)")
    notes: list[str] = []
    langs_ok = 0
    for lang, heading in (("en", "Executive summary"), ("tr", "Yönetici özeti")):
        facts = build_audit(report, authorisation=auth, bundle=loaded.info, lang=lang, auditor="Bench", client="Lab Org (fixture)", generated_at=now())
        target = folder / lang
        write_audit(target, facts, Branding(language=lang, auditor="Bench", client="Lab Org (fixture)"), pdf=False)
        shutil.copyfile(bundle, target / "proof.scrutator")
        page = (target / "audit.html").read_text(encoding="utf-8")
        checks = check_audit(target / "audit.html", target / "proof.scrutator")
        if heading in page and all(c.ok for c in checks):
            langs_ok += 1
        else:
            notes.append(f"{lang}: " + "; ".join(f"{c.name}: {c.detail}" for c in checks if not c.ok))
    en = folder / "en"
    facts = json.loads((en / "audit.json").read_text(encoding="utf-8"))
    unsupported = evidence_problems(facts, loaded.evidence_ids)
    notes += unsupported[:3]
    checks = check_audit(en / "audit.html", en / "proof.scrutator")
    # branding as an attacker would write it
    hostile = Branding(auditor=HOSTILE_TEXT, contact=HOSTILE_TEXT, client=HOSTILE_TEXT, language="en")
    page = render_audit(facts, hostile)
    inert = page.count("<script") == 1 and "<script>alert" not in page and "<img src=x" not in page and page.count("</style>") == 1
    # tampering
    original = (en / "audit.html").read_text(encoding="utf-8")
    cases = []

    def caught(page_text: str, bundle_path: Path, check_name: str) -> bool:
        (folder / "tampered.html").write_text(page_text, encoding="utf-8", newline="\n")
        result = {c.name: c.ok for c in check_audit(folder / "tampered.html", bundle_path)}
        return result.get(check_name) is False

    cases.append(caught(original.replace(f"{facts['summary']['risks']} issue", f"{max(0, facts['summary']['risks'] - 1)} issue", 1), en / "proof.scrutator", "page is what the facts render to"))
    embedded = read_embedded(original)
    forged = dict(embedded["facts"], risks=[r for r in embedded["facts"]["risks"] if r["severity"] != "high"])
    cases.append(caught(render_audit(forged, Branding.from_dict(embedded["branding"])), en / "proof.scrutator", "content derivable"))
    flipped = bytearray(bundle.read_bytes())
    flipped[len(flipped) // 2] ^= 1
    (folder / "flipped.scrutator").write_bytes(bytes(flipped))
    cases.append(caught(original, folder / "flipped.scrutator", "bundle verifies"))
    metrics = {
        "claims_without_evidence": _metric(len(unsupported), "= 0", not unsupported),
        "audit_check_passes": _metric(sum(c.ok for c in checks), f"= {len(checks)}", all(c.ok for c in checks)),
        "branding_injection_inert": _metric(inert, "= true", inert),
        "tamper_detected": _metric(sum(cases), f"= {len(cases)}", all(cases)),
        "languages_rendered_and_checked": _metric(langs_ok, "= 2", langs_ok == 2),
        "risks_in_audit": _metric(len(facts["risks"]), f"= {len(report['risks'])}", len(facts["risks"]) == len(report["risks"])),
    }
    return metrics, notes


# ------------------------------------------------------------------------------------------- bounty


def _report(names: dict[str, list[str]], risks: list[dict], ports: dict[str, list[int]], certs: list[tuple[int, str]]) -> dict:
    """A minimal report with the sections `monitor.snapshot` reads."""
    evidence = {}
    rows = []
    for name, addresses in names.items():
        eid = f"{abs(hash(('dns', name))) % 16**12:012x}".ljust(64, "0")
        evidence[eid] = {"source": "dns", "request": f"DNS A {name}", "payload": " ".join(addresses), "collected_at": "2026-10-21T00:00:00+00:00"}
        rows.append({"name": name, "tier": "verified", "addresses": addresses, "evidence_ids": [eid]})
    exposure = []
    for ip, open_ports in ports.items():
        eid = f"{abs(hash(('idb', ip))) % 16**12:012x}".ljust(64, "1")
        evidence[eid] = {"source": "internetdb", "request": f"GET https://internetdb.shodan.io/{ip}", "payload": "{}", "collected_at": "2026-10-21T00:00:00+00:00"}
        exposure.append({"ip": ip, "ports": open_ports, "evidence_ids": [eid]})
    if certs:
        eid = "c" * 64
        evidence[eid] = {"source": "crtsh", "request": "GET https://crt.sh/?q=%25.example.com&output=json",
                         "payload": json.dumps([{"id": i, "name_value": n, "not_before": "2026-10-20T00:00:00"} for i, n in certs]), "collected_at": "2026-10-21T00:00:00+00:00"}
    return {"names": rows, "risks": risks, "exposure": exposure, "evidence": evidence}


def _takeover(host: str) -> dict:
    return {"rule_id": "dangling-cname-claimable", "severity": "high", "title": "CNAME to a claimable service that no longer exists",
            "entity_ids": [f"domain:{host}", "domain:x.azurewebsites.net"], "explanation": f"{host} is an alias of a missing resource.",
            "evidence_ids": ["d" * 64], "fingerprint": f"fp-{host}"}


def bounty_metrics() -> tuple[dict, list[str]]:
    notes: list[str] = []
    refused = [t for t in HOSTILE_SCOPE if parse_target(t, True)[0] is None]
    notes += [f"accepted hostile entry {t!r}" for t in HOSTILE_SCOPE if t not in refused]
    normalised = sum(1 for t, (kind, value) in SAFE_SCOPE.items() if (r := parse_target(t, True)[0]) is not None and (r.kind, r.value) == (kind, value))
    big = False
    try:
        parse_scope(b"a.example.com\n" * 500_000)
    except ValueError:
        big = True
    data = b"*.example.com\nwww.example.net\n!*.out.example.com\n!legacy.example.com\n"
    scope = BountyScope.from_parsed(parse_scope(data), program="bench", data=data, name="scope.txt")
    membership = {"a.example.com": True, "www.example.net": True, "example.com": False, "x.out.example.com": False, "out.example.com": False,
                  "legacy.example.com": False, "example.com.evil.test": False, "other.example.net": False}
    wrong = [h for h, want in membership.items() if scope.contains(h) != want]
    notes += [f"membership wrong for {h}" for h in wrong]
    # a fixture history: baseline, then new in-scope and out-of-scope assets, then the same again
    history = [
        _report({"www.example.com": ["1.1.1.1"]}, [], {"1.1.1.1": [443]}, [(1, "www.example.com")]),
        _report({"www.example.com": ["1.1.1.1"], "dev.example.com": ["1.1.1.2"], "staging.out.example.com": ["1.1.1.3"], "legacy.example.com": ["1.1.1.4"]},
                [_takeover("shop.example.com"), _takeover("cdn.out.example.com")], {"1.1.1.1": [443, 6379], "1.1.1.3": [22]},
                [(1, "www.example.com"), (2, "dev.example.com"), (3, "staging.out.example.com")]),
    ]
    history.append(history[1])
    expected = {"name:dev.example.com", "risk:fp-shop.example.com", "svc:1.1.1.1:6379", "cert:crtsh:2"}
    previous, alerted, announced = None, set(), []
    for report in history:
        snap = snapshot(report, scope.contains)
        fresh, alerted = dedupe(diff_snapshots(previous, snap), alerted, current_keys(snap))
        announced.append({a.key for a in fresh})
        previous = snap
    got = announced[1]
    out_of_scope = [k for k in set().union(*announced) if "out.example.com" in k or "legacy" in k or "1.1.1.3" in k]
    notes += [f"expected {sorted(expected - got)}, extra {sorted(got - expected)}"] if got != expected else []
    metrics = {
        "hostile_entries_refused": _metric(len(refused), f"= {len(HOSTILE_SCOPE)}", len(refused) == len(HOSTILE_SCOPE)),
        "safe_entries_normalised": _metric(normalised, f"= {len(SAFE_SCOPE)}", normalised == len(SAFE_SCOPE)),
        "oversized_input_refused": _metric(big, "= true", big),
        "membership_errors": _metric(len(wrong), "= 0", not wrong),
        "baseline_alerts": _metric(len(announced[0]), "= 0", not announced[0]),
        "new_assets_detected": _metric(len(got & expected), f"= {len(expected)}", got == expected),
        "out_of_scope_announced": _metric(len(out_of_scope), "= 0", not out_of_scope),
        "repeat_announcements": _metric(len(announced[2]), "= 0", not announced[2]),
    }
    return metrics, notes


# ------------------------------------------------------------------------------------------- monitor


def monitor_metrics() -> tuple[dict, list[str]]:
    everything = lambda host: True  # noqa: E731
    low = {"rule_id": "caa-missing", "severity": "low", "title": "No CAA record at a zone apex", "entity_ids": ["domain:example.com"],
           "explanation": "no CAA", "evidence_ids": ["e" * 64], "fingerprint": "fp-caa"}
    sequence = [  # (report, kinds expected to be announced)
        (_report({"www.example.com": ["1.1.1.1"]}, [], {}, []), set()),
        (_report({"www.example.com": ["1.1.1.1"]}, [low], {}, []), {"new_risk"}),
        (_report({"www.example.com": ["1.1.1.1"]}, [low], {}, []), set()),
        (_report({"www.example.com": ["1.1.1.1"]}, [], {}, []), {"resolved_risk"}),
        (_report({"www.example.com": ["1.1.1.1"]}, [], {}, []), set()),
        (_report({"www.example.com": ["1.1.1.1"]}, [low], {}, []), {"new_risk"}),
        (_report({}, [low], {}, []), {"gone_name"}),
    ]
    previous, alerted, wrong, total = None, set(), [], 0
    for index, (report, want) in enumerate(sequence):
        snap = snapshot(report, everything)
        fresh, alerted = dedupe(diff_snapshots(previous, snap), alerted, current_keys(snap))
        total += len(fresh)
        if {a.kind for a in fresh} != want:
            wrong.append(f"step {index}: {sorted(a.kind for a in fresh)} instead of {sorted(want)}")
        previous = snap
    mixed = diff_snapshots(snapshot(sequence[0][0], everything), snapshot(_report({"www.example.com": ["1.1.1.1"], "a.example.com": ["1.1.1.5"]}, [_takeover("b.example.com")], {}, []), everything))
    ordered = [a.severity for a in mixed] == sorted([a.severity for a in mixed], key=["high", "medium", "low", "info"].index)
    filtered = {a.severity for a in at_least(mixed, "high")} == {"high"}
    digest = render_digest("Client", [{**a.to_dict(), "at": "2026-10-21T00:00:00+00:00"} for a in mixed], period="2026-W43")
    cites = all(i[:12] in digest for a in mixed for i in a.evidence_ids[:1])
    metrics = {
        "dedupe_sequence_errors": _metric(len(wrong), "= 0", not wrong),
        "announcements": _metric(total, "= 4", total == 4),
        "severity_ordered": _metric(ordered, "= true", ordered),
        "min_severity_filter": _metric(filtered, "= true", filtered),
        "digest_cites_evidence": _metric(cites, "= true", cites),
    }
    return metrics, wrong
