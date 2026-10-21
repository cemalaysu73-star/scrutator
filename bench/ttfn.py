#!/usr/bin/env python
"""Speed as a user feels it: time to the first live name, `quick`, and the full scan, versions taking turns.

    python bench/ttfn.py owasp.org --runs 3 --gap 90 --keys KEYDIR --work DIR \
        --variant before=/path/to/old/src --variant after=/path/to/new/src --out times.json

Per round and per variant it runs the benchmark's own command (`scan <target> --format json --ai off --no-summary
--bundle`) in a child process with PYTHONPATH set to that version's `src`, and reads its output line by line as it
comes. For a version that prints live names (`--live`, R6) it records when the first one arrived (any name, and the
first name below the apex). A version without the live list shows a name to its user only in the report it writes at
the end, so its time to the first name is the time the process ended. A variant whose label ends in `+quick` also runs
`scrutator quick <target> --bundle` (R6) in the same round.

Seconds are wall time from starting the child process (Python start-up included) until the line arrived or the process
ended. Between two runs it waits `--gap` seconds, so the versions see the same state of the public sources.

Only the frozen benchmark targets and example.com are queried.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

ALLOWED = {"zonetransfer.me", "example.com", "nmap.org", "owasp.org"}


def run(cmd: list[str], src: str, target: str) -> dict:
    env = {**os.environ, "PYTHONPATH": src, "PYTHONUNBUFFERED": "1"}
    started = time.perf_counter()
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    first_any = first_sub = None
    lines: list[str] = []
    err: list[str] = []
    threading.Thread(target=lambda: err.extend(proc.stderr), daemon=True).start()
    for line in proc.stdout:
        now = time.perf_counter() - started
        lines.append(line.rstrip("\n"))
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "live":
            if first_any is None:
                first_any = now
            if first_sub is None and parts[1] != target:
                first_sub = now
    proc.wait(timeout=1200)
    seconds = time.perf_counter() - started
    return {
        "seconds": round(seconds, 2),
        "exit": proc.returncode,
        "first_live_name_s": round(first_any, 2) if first_any is not None else None,
        "first_live_subdomain_s": round(first_sub, 2) if first_sub is not None else None,
        "live_lines": sum(1 for line in lines if line.split()[:1] == ["live"]),
        "stdout_tail": lines[-12:],
        "stderr_tail": [e.rstrip() for e in err[-5:]],
    }


def describe(out: Path) -> dict:
    report_path = out / "report.json"
    if not report_path.exists():
        return {}
    report = json.loads(report_path.read_text(encoding="utf-8"))
    names = report.get("names", [])
    return {
        "version": report["tool"]["version"],
        "live": sorted(r["name"] for r in names if r["state"] == "live"),
        "verified": sorted(r["name"] for r in names if r.get("tier") == "verified"),
        "headline": report["summary"].get("headline"),
        "evidence": len(report["evidence"]),
        "failed": sorted(m for m, h in report["sources"].items() if h["error"] or h.get("down")),
        "deadline_hit": report["coverage"]["deadline_hit"],
        "bundle": (out / "proof.scrutator").exists(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--gap", type=float, default=90.0)
    parser.add_argument("--variant", action="append", required=True, help="LABEL=path/to/src; LABEL ending in +quick also runs quick")
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--keys", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()
    if args.target not in ALLOWED:
        print(f"refusing {args.target!r}", file=sys.stderr)
        return 2
    variants = [v.split("=", 1) for v in args.variant]
    results: list[dict] = []
    first = True
    for round_no in range(1, args.runs + 1):
        for label, src in variants:
            jobs = [("scan", ["scan", args.target, "--format", "json", "--ai", "off", "--no-summary", "--bundle"])]
            if label.endswith("+quick"):
                jobs[0][1].append("--live")
                jobs.append(("quick", ["quick", args.target, "--bundle"]))
            for kind, sub in jobs:
                if not first:
                    time.sleep(args.gap)
                first = False
                out = args.work / f"{label.replace('+', '_')}-{kind}-run{round_no}"
                out.mkdir(parents=True, exist_ok=True)
                cmd = [sys.executable, "-m", "scrutator", *sub, "--out", str(out), "--key-dir", str(args.keys)]
                entry = {"variant": label, "kind": kind, "run": round_no, "at": time.strftime("%Y-%m-%dT%H:%M:%S"), **run(cmd, src, args.target)}
                entry.update(describe(out))
                if entry["first_live_name_s"] is None:
                    entry["first_name_visible_s"] = entry["seconds"]  # only in the report written at the end
                else:
                    entry["first_name_visible_s"] = entry["first_live_subdomain_s"] or entry["first_live_name_s"]
                results.append(entry)
                print(f"{label} {kind} run {round_no}: {entry['seconds']} s, first name visible {entry['first_name_visible_s']} s, "
                      f"{len(entry.get('live', []))} live, failed: {entry.get('failed')}", flush=True)
                if args.out:
                    args.out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    for label, _ in variants:
        for kind in ("scan", "quick"):
            rows = [r for r in results if r["variant"] == label and r["kind"] == kind]
            if rows:
                print(f"{label} {kind}: median {statistics.median(r['seconds'] for r in rows):.1f} s, first name visible median "
                      f"{statistics.median(r['first_name_visible_s'] for r in rows):.1f} s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
