#!/usr/bin/env python
"""Reproducible head-to-head benchmark: Scrutator against passive subdomain/recon tools.

One command:  python bench/run_bench.py            (see bench/README.md)

What it does, per target and per tool:
  1. run the tool with a fixed timeout, passive modes only, keyless (exact commands are recorded);
  2. normalise the output to a set of hostnames inside the target's scope;
  3. resolve every hostname with dnspython (A/AAAA, following CNAMEs) to split live from stale;
  4. score recall / precision against the truth set, names unique to the tool, wall time.
For Scrutator it also computes the evidence-backed share, findings, risks, bundle verification,
a tamper test and the sources that failed.

Only the targets listed in TARGETS are ever queried. Nothing here brute forces, scans ports,
crawls, or needs an account or key. The AXFR against the zonetransfer.me test name server is the
single active request, made once (zone published for exactly that purpose) and cached.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import dns.exception
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
ADAPTERS = ROOT / "adapters"

# Frozen in docs/benchmark-protocol.md before the first run. Do not add targets without writing them there first.
TARGETS = {
    "zonetransfer.me": {"truth": "axfr", "axfr_server": "nsztm1.digi.ninja"},
    "example.com": {"truth": "pseudo"},
    "nmap.org": {"truth": "pseudo"},
    "owasp.org": {"truth": "pseudo"},
}

RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
HOST_RE = re.compile(r"^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
STDOUT_KEEP = 64 * 1024


# ---------------------------------------------------------------------------------------------
# helpers


def normalise(raw: set[str] | list[str], target: str) -> tuple[set[str], dict]:
    """Lower-case, strip trailing dots and wildcard prefixes, keep valid hostnames strictly below
    the target apex. The apex itself is excluded for every tool (the seed is not a discovery)."""
    names: set[str] = set()
    dropped = {"wildcard": 0, "out_of_scope": 0, "invalid": 0, "apex": 0}
    for item in raw:
        name = str(item).strip().lower().rstrip(".")
        if name.startswith("*."):
            dropped["wildcard"] += 1
            name = name[2:]
        if name == target:
            dropped["apex"] += 1
            continue
        if not name.endswith("." + target):
            dropped["out_of_scope"] += 1
            continue
        if not HOST_RE.match(name):
            dropped["invalid"] += 1
            continue
        names.add(name)
    return names, dropped


def make_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = list(RESOLVERS)
    resolver.lifetime = 6.0
    resolver.timeout = 3.0
    return resolver


def resolve_one(name: str) -> dict:
    """live = has an A or AAAA answer (CNAME chains followed). stale = NXDOMAIN or no address.
    error = could not tell (timeouts etc.); errors are retried once and counted separately."""
    resolver = make_resolver()
    outcome = "stale"
    cname = False
    addrs: set[str] = set()
    for attempt in range(2):
        outcome = "stale"
        saw_error = False
        for rtype in ("A", "AAAA"):
            try:
                answer = resolver.resolve(name, rtype)
                cname = cname or any(rr.rdtype == dns.rdatatype.CNAME for rr in answer.response.answer)
                addrs.update(rr.to_text() for rr in answer)
                outcome = "live"
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                continue
            except (dns.exception.Timeout, dns.exception.DNSException):
                saw_error = True
        if outcome == "live" or not saw_error:
            break
        outcome = "error"
    return {"status": outcome, "via_cname": cname, "addrs": sorted(addrs)}


def resolve_many(names: set[str], cache: dict[str, dict]) -> dict[str, dict]:
    todo = sorted(n for n in names if n not in cache)
    if todo:
        with cf.ThreadPoolExecutor(max_workers=24) as pool:
            for name, result in zip(todo, pool.map(resolve_one, todo)):
                cache[name] = result
    return cache


def wildcard_probe(target: str) -> set[str]:
    """Addresses a random, certainly-unregistered label under the target resolves to (three probes).
    Empty set = no wildcard DNS at the apex. (Wildcards deeper in the tree are not probed.)"""
    addrs: set[str] = set()
    for _ in range(3):
        label = "bench-" + "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(16))
        result = resolve_one(f"{label}.{target}")
        if result["status"] == "live":
            addrs.update(result["addrs"])
    return addrs


def classify(name: str, cache: dict[str, dict], wildcard: set[str]) -> str:
    """live: resolves, and (if the apex has a wildcard) to something other than the wildcard
    answer. wildcard: resolves only to the wildcard address set, so its existence is unproven.
    stale: NXDOMAIN/no address. error: could not be determined."""
    entry = cache[name]
    if entry["status"] != "live":
        return entry["status"]
    if wildcard and set(entry.get("addrs", [])) <= wildcard:
        return "wildcard"
    return "live"


def kill_tree(proc: subprocess.Popen) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
    else:
        proc.kill()


@dataclass
class Run:
    cmd: list[str]
    seconds: float
    exit_code: int | None
    timed_out: bool
    stdout: str
    stderr: str


def run_cmd(cmd: list[str], timeout: int, cwd: Path, env: dict | None = None) -> Run:
    full_env = dict(os.environ)
    full_env.update({"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1", "NO_COLOR": "1", "COLUMNS": "200"})
    if env:
        full_env.update(env)
    started = time.monotonic()
    proc = subprocess.Popen(
        cmd, cwd=cwd, env=full_env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace",
    )
    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        kill_tree(proc)
        try:
            out, err = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            out, err = "", ""
    return Run(cmd, round(time.monotonic() - started, 2), None if timed_out else proc.returncode, timed_out, out or "", err or "")


def venv_exe(venv: Path, name: str) -> Path:
    scripts = venv / ("Scripts" if os.name == "nt" else "bin")
    for candidate in (scripts / f"{name}.exe", scripts / name):
        if candidate.exists():
            return candidate
    return scripts / name


def pip_version(venv: Path, package: str) -> str:
    try:
        py = venv_exe(venv, "python")
        out = subprocess.run([str(py), "-m", "pip", "show", package], capture_output=True, text=True, timeout=60).stdout
        match = re.search(r"^Version:\s*(\S+)", out, re.M)
        return match.group(1) if match else "unknown"
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------------------------
# truth: AXFR for zonetransfer.me


PUBLISHED_ZONE_URL = "https://digi.ninja/projects/zonetransferme.php"
RR_LINE = re.compile(r"^(\S+)\s+\d+\s+IN\s+([A-Z0-9]+)", re.I)


def owners_from_dump(lines: list[str], target: str) -> dict:
    owners: set[str] = set()
    hosts: set[str] = set()
    records = 0
    for line in lines:
        match = RR_LINE.match(line.strip())
        if not match:
            continue
        owner = match.group(1).rstrip(".").lower()
        if owner != target and not owner.endswith("." + target):
            continue
        records += 1
        owners.add(owner)
        if match.group(2).upper() in ("A", "AAAA", "CNAME"):
            hosts.add(owner)
    return {"all": owners, "hosts": hosts, "records": records}


def fetch_truth_zone(target: str, server: str, dest: Path, refresh: bool) -> dict:
    """Ground truth for the test zone. One AXFR against the published test name server, cached.
    If the transfer does not complete (some networks drop it), fall back to the dig AXFR dump the
    zone's author publishes on the project page, and record which source was used. A failed AXFR
    leaves `axfr.failed.txt`, so reruns do not repeat the transfer (use --refresh-axfr)."""
    cached = dest / "zone.truth.txt"
    failed = dest / "axfr.failed.txt"
    if cached.exists() and not refresh:
        lines = cached.read_text(encoding="utf-8").splitlines()
        source = lines[0].lstrip("# ").strip()
        out = owners_from_dump(lines, target)
        out["source"] = source
        return out
    if refresh and failed.exists():
        failed.unlink()
    if not failed.exists():
        try:
            address = make_resolver().resolve(server, "A")[0].to_text()
            zone = dns.zone.from_xfr(dns.query.xfr(address, target, lifetime=30, timeout=20), relativize=False)
            text = "# AXFR from " + server + " (live)\n" + zone.to_text(relativize=False).replace("\t", " ")
            cached.write_text(text, encoding="utf-8")
            out = owners_from_dump(zone.to_text(relativize=False).splitlines(), target)
            out["source"] = f"AXFR from {server} (live)"
            return out
        except Exception as exc:  # timeout, refused, network filtering
            failed.write_text(f"AXFR against {server} did not complete: {type(exc).__name__} {exc}\n", encoding="utf-8")
    import httpx

    page = httpx.get(PUBLISHED_ZONE_URL, timeout=30, follow_redirects=True).text
    text = re.sub(r"<[^>]+>", "\n", page)
    block = text.split("dig axfr", 1)[-1].split(";; Query time", 1)[0]
    lines = [l for l in block.splitlines() if l.strip()]
    cached.write_text("# AXFR dump published by the zone's author at " + PUBLISHED_ZONE_URL + " (live AXFR did not complete from this network)\n" + "\n".join(lines) + "\n", encoding="utf-8")
    out = owners_from_dump(lines, target)
    out["source"] = "published dig AXFR dump (" + PUBLISHED_ZONE_URL + ")"
    return out


# ---------------------------------------------------------------------------------------------
# tools


@dataclass
class ToolResult:
    tool: str
    target: str
    status: str  # ok | timeout | error | not_run
    seconds: float
    command: str
    raw_names: set[str] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)


def parse_lines_for_hosts(text: str, target: str) -> set[str]:
    return set(re.findall(r"[A-Za-z0-9_*.-]+\." + re.escape(target), text, flags=re.I))


def run_sublist3r(ctx: "Ctx", target: str, workdir: Path) -> ToolResult:
    exe = venv_exe(ctx.bench_venv, "sublist3r")
    out_file = workdir / "sublist3r.out.txt"
    # Passive: no -b (bruteforce), no -p (port scan). All default engines.
    cmd = [str(exe), "-d", target, "-n", "-o", str(out_file)]
    result = run_cmd(cmd, ctx.timeout, workdir)
    save_stdio(workdir, "sublist3r", result)
    names: set[str] = set()
    if out_file.exists():
        names |= {l.strip() for l in out_file.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()}
    notes = [l.strip() for l in (result.stdout + "\n" + result.stderr).splitlines() if "[!]" in l and "Coloring" not in l]
    status = "timeout" if result.timed_out else ("ok" if names or result.exit_code == 0 else "error")
    return ToolResult("sublist3r", target, status, result.seconds, " ".join(cmd), names, notes[:6])


def run_dnsrecon(ctx: "Ctx", target: str, workdir: Path) -> ToolResult:
    exe = venv_exe(ctx.bench_venv, "dnsrecon")
    out_file = workdir / "dnsrecon.out.json"
    # Passive: only the crt.sh type; the NS recursion and BIND-version probes against the target's
    # own name servers are disabled. No std (SRV guessing), no axfr, no brt.
    cmd = [str(exe), "-d", target, "-t", "crt", "--disable_check_recursion", "--disable_check_bindversion", "-j", str(out_file)]
    result = run_cmd(cmd, ctx.timeout, workdir)
    save_stdio(workdir, "dnsrecon", result)
    names: set[str] = set()
    if out_file.exists():
        try:
            for record in json.loads(out_file.read_text(encoding="utf-8")):
                if record.get("type") == "ScanInfo":
                    continue
                for key in ("name", "target", "domain", "mname"):
                    if isinstance(record.get(key), str) and record[key].lower().endswith(target):
                        names.add(record[key])
        except (json.JSONDecodeError, OSError):
            pass
    names |= parse_lines_for_hosts(result.stdout, target) - {target}
    notes = [l.strip() for l in result.stdout.splitlines() if "error" in l.lower() or "fail" in l.lower()]
    status = "timeout" if result.timed_out else ("ok" if result.exit_code == 0 else "error")
    return ToolResult("dnsrecon (crt)", target, status, result.seconds, " ".join(cmd), names, notes[:6])


def run_knock(ctx: "Ctx", target: str, workdir: Path) -> ToolResult:
    py = venv_exe(ctx.bench_venv, "python")
    cmd = [str(py), str(ADAPTERS / "knock_recon.py"), target]
    home = ctx.work / "home"
    home.mkdir(parents=True, exist_ok=True)
    result = run_cmd(cmd, ctx.timeout, workdir, env={"USERPROFILE": str(home), "HOME": str(home)})
    save_stdio(workdir, "knockpy", result)
    names: set[str] = set()
    extra: dict = {}
    try:
        data = json.loads(result.stdout.strip().splitlines()[-1])
        names = set(data.get("names", []))
        extra["services"] = data.get("services", [])
    except (json.JSONDecodeError, IndexError):
        pass
    status = "timeout" if result.timed_out else ("ok" if result.exit_code == 0 and extra else "error")
    notes = ["recon engine only (the CLI would also AXFR and HTTP-probe); keyless services: " + ", ".join(extra.get("services", []))]
    return ToolResult("knockpy (recon)", target, status, result.seconds, " ".join(cmd), names, notes, extra)


def run_scrutator(ctx: "Ctx", target: str, workdir: Path) -> ToolResult:
    out = ctx.work / "scrutator" / target
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    exe = ctx.scrutator
    # AI off and no summary: the benchmark measures the deterministic collection. Otherwise defaults.
    cmd = [str(exe), "scan", target, "--out", str(out), "--format", "json", "--ai", "off", "--no-summary",
           "--bundle", "--key-dir", str(ctx.keydir)]
    result = run_cmd(cmd, ctx.timeout, workdir)
    save_stdio(workdir, "scrutator", result)
    report_path = out / "report.json"
    names: set[str] = set()
    extra: dict = {"out_dir": str(out)}
    notes: list[str] = []
    if report_path.exists():
        report = json.loads(report_path.read_text(encoding="utf-8"))
        extra.update(analyse_scrutator(ctx, report, out, target))
        names = set(extra.pop("_reported"))
        extra["version"] = report.get("tool", {}).get("version")
        notes = [f"{src}: {', '.join(info['errors'])}" for src, info in report.get("sources", {}).items() if info.get("error")]
    status = "timeout" if result.timed_out else ("ok" if report_path.exists() and result.exit_code == 0 else "error")
    return ToolResult("Scrutator", target, status, result.seconds, " ".join(cmd), names, notes, extra)


def analyse_scrutator(ctx: "Ctx", report: dict, out: Path, target: str) -> dict:
    """Evidence-backed share, findings, risks, sources that failed, bundle verification, tamper test."""
    evidence = report.get("evidence", {})
    cited: dict[str, set[str]] = {}

    def cite(entity_ids, evidence_ids):
        ids = {e for e in evidence_ids if e in evidence}
        for entity in entity_ids:
            cited.setdefault(entity, set()).update(ids)

    for edge in report.get("edges", []):
        cite([edge["src"], edge["dst"]], edge.get("evidence_ids", []))
    for finding in report.get("findings", []):
        cite(finding.get("entity_ids", []), finding.get("evidence_ids", []))
    for risk in report.get("risks", []):
        cite(risk.get("entity_ids", []), risk.get("evidence_ids", []))

    reported: dict[str, str] = {}
    for entity in report.get("entities", []):
        if entity["type"] == "domain":
            names, _ = normalise([entity["value"]], target)
            for name in names:
                reported[name] = entity["state"]

    claimed: dict[str, str] = {}
    for row in report.get("names", []):  # v0.6+: Scrutator's own resolution state for every in-scope name
        names, _ = normalise([row["name"]], target)
        for name in names:
            claimed[name] = row["state"]

    tiers: dict[str, str] = {}
    for row in report.get("names", []):  # v0.7+: how well the evidence supports each name
        if "tier" in row:
            names, _ = normalise([row["name"]], target)
            for name in names:
                tiers[name] = row["tier"]

    backed = strict = 0
    unbacked: list[str] = []
    for name in reported:
        ids = cited.get(f"domain:{name}", set())
        if ids:
            backed += 1
        else:
            unbacked.append(name)
        if any(name in (str(evidence[i].get("request", "")) + " " + str(evidence[i].get("payload", ""))).lower() for i in ids):
            strict += 1

    info: dict = {
        "_reported": sorted(reported),
        "states": {s: sum(1 for v in reported.values() if v == s) for s in sorted(set(reported.values()))},
        "name_states": claimed,
        "name_tiers": tiers,
        "headline": report.get("summary", {}).get("headline"),
        "findings_by_tier": report.get("summary", {}).get("findings_by_tier"),
        "source_policy": report.get("source_policy"),
        "hostnames_reported": len(reported),
        "evidence_backed": backed,
        "evidence_backed_strict": strict,
        "unbacked_examples": sorted(unbacked)[:5],
        "findings": len(report.get("findings", [])),
        "risks": len(report.get("risks", [])),
        "risk_rules": sorted({r.get("rule_id", "?") for r in report.get("risks", [])}),
        "evidence_records": len(evidence),
        "sources": {
            name: {"ok": s.get("ok", 0), "error": s.get("error", 0), "denied": s.get("denied", 0), "errors": s.get("errors", [])}
            for name, s in report.get("sources", {}).items()
        },
        "sources_failed": sorted(name for name, s in report.get("sources", {}).items() if s.get("error")),
    }

    bundle = out / "proof.scrutator"
    info["bundle_present"] = bundle.exists()
    if bundle.exists():
        pub = ctx.keydir / "signing.pub"
        verify = run_cmd([str(ctx.scrutator), "verify", str(bundle), "--pin", str(pub)], 300, out)
        info["verify_exit"] = verify.exit_code
        info["verify_passed"] = verify.exit_code == 0 and "Verification passed" in verify.stdout
        info["verify_output"] = verify.stdout.strip().splitlines()[-12:]
        info["tamper_detected"] = tamper_test(ctx, bundle, out)
    return info


def tamper_test(ctx: "Ctx", bundle: Path, out: Path) -> bool | None:
    """Change one byte of the evidence inside a copy of the bundle; verify must now fail."""
    tampered = out / "tampered.scrutator"
    try:
        with zipfile.ZipFile(bundle) as src, zipfile.ZipFile(tampered, "w", zipfile.ZIP_DEFLATED) as dst:
            for item in src.infolist():
                data = src.read(item.filename)
                if item.filename == "evidence.jsonl" and data:
                    index = len(data) // 2
                    data = data[:index] + bytes([data[index] ^ 0x01]) + data[index + 1:]
                dst.writestr(item.filename, data)
        verify = run_cmd([str(ctx.scrutator), "verify", str(tampered), "--pin", str(ctx.keydir / "signing.pub")], 300, out)
        return verify.exit_code != 0
    except Exception:
        return None
    finally:
        tampered.unlink(missing_ok=True)


def save_stdio(workdir: Path, tool: str, result: Run) -> None:
    (workdir / f"{tool}.cmd.txt").write_text(" ".join(result.cmd) + f"\n# exit={result.exit_code} timed_out={result.timed_out} seconds={result.seconds}\n", encoding="utf-8")
    text = result.stdout if len(result.stdout) <= STDOUT_KEEP else result.stdout[:STDOUT_KEEP] + "\n[truncated]\n"
    (workdir / f"{tool}.stdout.txt").write_text(text, encoding="utf-8")
    if result.stderr.strip():
        err = result.stderr if len(result.stderr) <= STDOUT_KEEP else result.stderr[:STDOUT_KEEP] + "\n[truncated]\n"
        (workdir / f"{tool}.stderr.txt").write_text(err, encoding="utf-8")


def save_result(workdir: Path, tool: str, res: ToolResult) -> None:
    data = {"tool": res.tool, "target": res.target, "status": res.status, "seconds": res.seconds, "command": res.command,
            "raw_names": sorted(res.raw_names), "notes": res.notes, "extra": {k: v for k, v in res.extra.items() if k != "out_dir"}}
    (workdir / f"{tool}.result.json").write_text(json.dumps(data, indent=1), encoding="utf-8")
    (workdir / f"{tool}.names.txt").write_text("\n".join(sorted(res.raw_names)) + "\n", encoding="utf-8")


def load_result(src: Path, tool: str, workdir: Path) -> ToolResult | None:
    path = src / f"{tool}.result.json"
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    for file in src.glob(f"{tool}.*"):
        if file.is_file() and src.resolve() != workdir.resolve():
            shutil.copy2(file, workdir / file.name)
    return ToolResult(data["tool"], data["target"], data["status"], data["seconds"], data["command"], set(data["raw_names"]), data["notes"], data["extra"])


TOOL_RUNNERS = {
    "scrutator": run_scrutator,
    "sublist3r": run_sublist3r,
    "dnsrecon": run_dnsrecon,
    "knockpy": run_knock,
}

NOT_RUN = {
    "subfinder": "needs a Go binary (GitHub release or `go install`); `go` is not installed. Needs the user's approval.",
    "Amass": "needs a Go binary (GitHub release or `go install`). Needs the user's approval.",
    "SpiderFoot": "not on PyPI as the official tool; official install is a git clone or release download. Needs the user's approval.",
    "theHarvester": "the PyPI name `theHarvester` is an unrelated 0.0.1 placeholder; the real tool installs from a git clone. Needs the user's approval.",
}


@dataclass
class Ctx:
    bench_venv: Path
    scrutator: Path
    work: Path
    keydir: Path
    timeout: int


# ---------------------------------------------------------------------------------------------
# scoring and tables


def pct(num: int, den: int) -> str:
    return "n/a" if den == 0 else f"{100 * num / den:.0f}%"


def score(results: list[ToolResult], target: str, truth_kind: str, axfr: dict | None, cache: dict, wildcard: set[str]) -> dict:
    found: dict[str, set[str]] = {}
    dropped: dict[str, dict] = {}
    for r in results:
        found[r.tool], dropped[r.tool] = normalise(r.raw_names, target)

    universe = set().union(*found.values()) if found else set()
    resolve_many(universe, cache)
    cls = {n: classify(n, cache, wildcard) for n in universe}
    live = {n for n, c in cls.items() if c == "live"}

    if truth_kind == "axfr":
        truth = set(axfr["all"]) - {target}
        truth_hosts = set(axfr["hosts"]) - {target}
        truth_label = f"zone owner names below the apex, source: {axfr['source']} ({len(truth)} names, {len(truth_hosts)} with A/AAAA/CNAME)"
    else:
        truth = live
        truth_hosts = live
        truth_label = f"pseudo-truth: union of live names found by any tool ({len(truth)} names)"

    rows = []
    for r in results:
        names = found[r.tool]
        count = lambda kind: sum(1 for n in names if cls[n] == kind)
        others = set().union(*(found[o.tool] for o in results if o.tool != r.tool)) if len(results) > 1 else set()
        unique = names - others
        tp = names & truth
        judged = len(names) - count("wildcard")
        rows.append({
            "tool": r.tool, "status": r.status, "seconds": r.seconds,
            "found": len(names), "live": count("live"), "wildcard_covered": count("wildcard"), "stale": count("stale"), "resolve_errors": count("error"),
            "true_positives": len(tp),
            "recall": pct(len(tp), len(truth)), "recall_hosts": pct(len(names & truth_hosts), len(truth_hosts)),
            # precision: zone target = share inside the zone; pseudo targets = share live among the names that can be judged
            "precision": pct(len(tp), len(names)) if truth_kind == "axfr" else pct(count("live"), judged),
            "unique": len(unique), "unique_live": len(unique & live),
            "dropped": dropped[r.tool], "notes": r.notes, "command": r.command,
        })
    for r, row in zip(results, rows):
        claim = r.extra.get("name_states") if r.tool == "Scrutator" else None
        if claim:
            marked = {n for n, state in claim.items() if state == "live" and n in found[r.tool]}
            row["claims"] = {
                "marked_live": len(marked),
                "confirmed_live": len(marked & live),
                "marked_live_but_not_live": sorted(marked - live)[:20],
                "live_not_marked_live": sorted((found[r.tool] & live) - marked)[:20],
                "by_state": {s: sum(1 for n, v in claim.items() if v == s and n in found[r.tool]) for s in ("live", "stale", "wildcard", "unresolved")},
                "precision_of_marked_live": pct(len(marked & live), len(marked)),
                "recall_of_marked_live": pct(len(marked & truth), len(truth)),
            }
    for r, row in zip(results, rows):
        tiers = r.extra.get("name_tiers") if r.tool == "Scrutator" else None
        if tiers:
            verified = {n for n, t in tiers.items() if t == "verified" and n in found[r.tool]}
            count_tier = {t: sum(1 for n, v in tiers.items() if v == t and n in found[r.tool]) for t in ("verified", "claimed", "stale", "wildcard")}
            row["tiers"] = {
                "counts": count_tier,
                "verified_live": len(verified & live),
                "verified_not_live": sorted(verified - live)[:20],
                "live_not_verified": sorted((found[r.tool] & live) - verified)[:20],
                "precision_of_verified": pct(len(verified & live), len(verified)),
                "recall_of_verified": pct(len(verified & truth), len(truth)),
                "verified_share_of_headline": pct(count_tier["verified"], count_tier["verified"] + count_tier["claimed"]),
                "headline": r.extra.get("headline"),
            }
    return {
        "target": target, "truth_kind": truth_kind, "truth_label": truth_label, "truth_size": len(truth),
        "truth_hosts_size": len(truth_hosts), "wildcard_dns": sorted(wildcard), "rows": rows,
        "names": {tool: sorted(n) for tool, n in found.items()},
        "classes": {n: cls[n] for n in sorted(universe)},
        "missed_by_all": sorted(truth - universe)[:60] if truth_kind == "axfr" else [],
        "universe": len(universe), "live_universe": len(live),
    }


def render_tables(scored: list[dict], results: dict[str, list[ToolResult]], meta: dict) -> str:
    lines = [f"# Benchmark tables ({meta['date']})", "",
             f"Resolvers: {', '.join(RESOLVERS)}. Timeout per tool run: {meta['timeout']} s. Scrutator {meta.get('scrutator_version')}, commit {meta.get('commit')}.", ""]
    for s in scored:
        lines += [f"## {s['target']}", "", f"Truth: {s['truth_label']}." + (f"  Wildcard DNS at this apex (random labels resolve to {', '.join(s['wildcard_dns'])}): names resolving only to those addresses are counted as wildcard-covered, not live, and excluded from the precision denominator." if s["wildcard_dns"] else ""), ""]
        lines += ["| Tool | Status | Names found | Live | Wildcard-covered | Stale/NX | Recall | Precision | Unique | Unique live | Time (s) |",
                  "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
        for r in s["rows"]:
            recall = r["recall"] if s["truth_kind"] == "pseudo" else f"{r['recall']} ({r['recall_hosts']} of host names)"
            lines.append(f"| {r['tool']} | {r['status']} | {r['found']} | {r['live']} | {r['wildcard_covered']} | {r['stale']} | {recall} | {r['precision']} | {r['unique']} | {r['unique_live']} | {r['seconds']} |")
        scr = next((r for r in results[s["target"]] if r.tool == "Scrutator"), None)
        if scr and scr.extra:
            e = scr.extra
            lines += ["", "Scrutator extras:", "",
                      "| Hostnames reported | Evidence-backed | Backed by evidence naming the host | Findings | Risks | Evidence records | Bundle verify (pinned, no replay) | Tamper detected | Sources failed |",
                      "|---:|---:|---:|---:|---:|---:|---|---|---|",
                      f"| {e.get('hostnames_reported')} | {pct(e.get('evidence_backed', 0), e.get('hostnames_reported', 0))} ({e.get('evidence_backed')}) | {pct(e.get('evidence_backed_strict', 0), e.get('hostnames_reported', 0))} ({e.get('evidence_backed_strict')}) | {e.get('findings')} | {e.get('risks')} | {e.get('evidence_records')} | {'PASS' if e.get('verify_passed') else 'FAIL' if 'verify_passed' in e else 'n/a'} | {e.get('tamper_detected')} | {', '.join(e.get('sources_failed', [])) or 'none'} |"]
        scr_row = next((r for r in s["rows"] if r["tool"] == "Scrutator" and r.get("claims")), None)
        if scr_row:
            c = scr_row["claims"]
            st = c["by_state"]
            lines += ["", "Scrutator's own name states (v0.6), checked against this harness's resolver:", "",
                      "| Marked live | Stale | Wildcard-covered | Unresolved | Marked live and live here | Marked live but not live here | Live here but not marked live | Precision of the live set | Recall of the live set |",
                      "|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
                      f"| {st['live']} | {st['stale']} | {st['wildcard']} | {st['unresolved']} | {c['confirmed_live']} | {len(c['marked_live_but_not_live'])}{'+' if len(c['marked_live_but_not_live']) >= 20 else ''} | {len(c['live_not_marked_live'])}{'+' if len(c['live_not_marked_live']) >= 20 else ''} | {c['precision_of_marked_live']} | {c['recall_of_marked_live']} |"]
        tier_row = next((r for r in s["rows"] if r["tool"] == "Scrutator" and r.get("tiers")), None)
        if tier_row:
            t = tier_row["tiers"]
            c = t["counts"]
            lines += ["", "Scrutator's name tiers (v0.7), checked against this harness's resolver (apex excluded):", "",
                      "| Headline | Verified | Claimed | Stale | Wildcard | Verified and live here | Precision of the verified set | Recall of the verified set | Verified share of verified+claimed | Live here but not verified |",
                      "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
                      f"| {t['headline']} | {c['verified']} | {c['claimed']} | {c['stale']} | {c['wildcard']} | {t['verified_live']} | {t['precision_of_verified']} | {t['recall_of_verified']} | {t['verified_share_of_headline']} | {len(t['live_not_verified'])}{'+' if len(t['live_not_verified']) >= 20 else ''} |"]
        if s["missed_by_all"]:
            lines += ["", f"Zone names no tool found (first {len(s['missed_by_all'])}): " + ", ".join(f"`{n}`" for n in s["missed_by_all"])]
        lines.append("")
    lines += ["## Not run", ""] + [f"- {tool}: {why}" for tool, why in NOT_RUN.items()] + [""]
    return "\n".join(lines)


# ---------------------------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--date", default=dt.date.today().isoformat(), help="results folder name (default: today)")
    parser.add_argument("--timeout", type=int, default=900, help="seconds per tool run (default 900)")
    parser.add_argument("--bench-venv", type=Path, default=Path(os.environ.get("BENCH_VENV", Path.home() / "bench-venv")), help="venv with dnsrecon, sublist3r, knock-subdomains")
    parser.add_argument("--scrutator", type=Path, default=None, help="scrutator executable (default: next to this Python, else PATH)")
    parser.add_argument("--targets", nargs="*", default=list(TARGETS), help="subset of the frozen targets")
    parser.add_argument("--tools", nargs="*", default=list(TOOL_RUNNERS), choices=list(TOOL_RUNNERS))
    parser.add_argument("--reuse-from", type=Path, default=None, help="results folder whose saved per-tool results are reused instead of running the tool again")
    parser.add_argument("--rerun", nargs="*", default=[], choices=list(TOOL_RUNNERS), help="with --reuse-from: tools to run anyway")
    parser.add_argument("--refresh-axfr", action="store_true", help="repeat the single AXFR instead of using the cached zone")
    args = parser.parse_args()

    for t in args.targets:
        if t not in TARGETS:
            parser.error(f"{t} is not one of the frozen targets: {', '.join(TARGETS)}")

    scrutator = args.scrutator
    if scrutator is None:
        local = venv_exe(Path(sys.executable).resolve().parent.parent, "scrutator")
        scrutator = local if local.exists() else Path(shutil.which("scrutator") or "scrutator")

    results_dir = ROOT / "results" / args.date
    work = ROOT / "work"
    results_dir.mkdir(parents=True, exist_ok=True)
    work.mkdir(exist_ok=True)
    keydir = work / "keys"
    ctx = Ctx(args.bench_venv, scrutator, work, keydir, args.timeout)

    if not keydir.joinpath("signing.key").exists():
        keydir.mkdir(parents=True, exist_ok=True)
        gen = run_cmd([str(scrutator), "keygen", "--key-dir", str(keydir)], 60, work)
        if gen.exit_code != 0:
            print("keygen failed:", gen.stdout, gen.stderr)
            return 2

    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=REPO, capture_output=True, text=True).stdout.strip()
    meta = {"date": args.date, "timeout": args.timeout, "commit": commit, "python": sys.version.split()[0], "resolvers": RESOLVERS,
            "versions": {"dnsrecon": pip_version(args.bench_venv, "dnsrecon"), "sublist3r": pip_version(args.bench_venv, "Sublist3r"),
                         "knock-subdomains": pip_version(args.bench_venv, "knock-subdomains")},
            "not_run": NOT_RUN}

    all_results: dict[str, list[ToolResult]] = {}
    scored: list[dict] = []
    cache_path = results_dir / "resolution.json"
    cache: dict[str, dict] = json.loads(cache_path.read_text()) if cache_path.exists() else {}

    for target in args.targets:
        spec = TARGETS[target]
        workdir = results_dir / target
        workdir.mkdir(exist_ok=True)
        print(f"== {target}", flush=True)
        axfr = None
        if spec["truth"] == "axfr":
            axfr = fetch_truth_zone(target, spec["axfr_server"], results_dir, args.refresh_axfr)
            print(f"   truth zone ({axfr['source']}): {len(axfr['all'])} owner names, {axfr['records']} records", flush=True)
        wildcard = wildcard_probe(target)
        results: list[ToolResult] = []
        for tool in args.tools:
            res = None
            if args.reuse_from and tool not in args.rerun:
                res = load_result(args.reuse_from / target, tool, workdir)
                if res:
                    print(f"   reusing saved {tool} result", flush=True)
            if res is None:
                print(f"   running {tool} ...", flush=True)
                res = TOOL_RUNNERS[tool](ctx, target, workdir)
            save_result(workdir, tool, res)
            print(f"   {res.tool}: {res.status}, {len(res.raw_names)} raw names, {res.seconds}s", flush=True)
            if res.tool == "Scrutator":
                meta["scrutator_version"] = res.extra.get("version") or meta.get("scrutator_version")
            results.append(res)
            (workdir / f"{tool}.names.txt").write_text("\n".join(sorted(res.raw_names)) + "\n", encoding="utf-8")
        all_results[target] = results
        s = score(results, target, spec["truth"], axfr, cache, wildcard)
        scored.append(s)
        # the resolution cache is saved after each target so an interrupted run keeps its work
        cache_path.write_text(json.dumps(cache, indent=1, sort_keys=True), encoding="utf-8")
        scr = next((r for r in results if r.tool == "Scrutator"), None)
        if scr:
            (workdir / "scrutator.summary.json").write_text(json.dumps({k: v for k, v in scr.extra.items() if k != "out_dir"}, indent=1), encoding="utf-8")

    (results_dir / "results.json").write_text(json.dumps({"meta": meta, "targets": scored}, indent=1), encoding="utf-8")
    tables = render_tables(scored, all_results, meta)
    (results_dir / "tables.md").write_text(tables, encoding="utf-8")
    print("\n" + tables)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
