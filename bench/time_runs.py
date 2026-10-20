#!/usr/bin/env python
"""Wall time of `scrutator scan` for two or more code versions, interleaved and spaced apart.

    python bench/time_runs.py owasp.org --runs 3 --gap 300 \
        --variant v0.6=/path/to/old/src --variant v0.7=/path/to/new/src --out times.json

Each run is the benchmark's own command (`scan <target> --format json --ai off --no-summary --bundle`) in a
child process with PYTHONPATH pointing at that version's `src`, so the seconds include Python start-up and
the signed bundle. The versions take turns (A B A B A B) with `--gap` seconds between consecutive runs, so
both see the same state of the public sources, and no source is asked more than once per gap. Per run it
keeps the seconds, the exit status, the set of live names, the names Scrutator calls verified (v0.7), the
sources that failed and the version that wrote the report.

Only the frozen benchmark targets and example.com are queried.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

ALLOWED = {"zonetransfer.me", "example.com", "nmap.org", "owasp.org"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--gap", type=float, default=300.0, help="seconds between two consecutive runs")
    parser.add_argument("--variant", action="append", required=True, help="LABEL=path/to/src (repeatable)")
    parser.add_argument("--work", type=Path, required=True, help="directory for the runs' output")
    parser.add_argument("--keys", type=Path, required=True, help="directory with signing.key")
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
            if not first:
                time.sleep(args.gap)
            first = False
            out = args.work / f"{label}-run{round_no}"
            out.mkdir(parents=True, exist_ok=True)
            cmd = [sys.executable, "-m", "scrutator", "scan", args.target, "--out", str(out), "--format", "json",
                   "--ai", "off", "--no-summary", "--bundle", "--key-dir", str(args.keys)]
            env = {**os.environ, "PYTHONPATH": src}
            started = time.perf_counter()
            done = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=1200)
            seconds = time.perf_counter() - started
            entry = {"variant": label, "run": round_no, "seconds": round(seconds, 1), "exit": done.returncode}
            report_path = out / "report.json"
            if report_path.exists():
                report = json.loads(report_path.read_text(encoding="utf-8"))
                names = report.get("names", [])
                entry.update(
                    version=report["tool"]["version"],
                    live=sorted(r["name"] for r in names if r["state"] == "live"),
                    verified=sorted(r["name"] for r in names if r.get("tier") == "verified"),
                    claimed=sum(1 for r in names if r.get("tier") == "claimed"),
                    headline=report["summary"].get("headline"),
                    entities=report["summary"]["entities"],
                    evidence=len(report["evidence"]),
                    failed=sorted(m for m, h in report["sources"].items() if h["error"] or h.get("down")),
                    deadline_hit=report["coverage"]["deadline_hit"],
                )
            results.append(entry)
            print(f"{label} run {round_no}: {entry['seconds']} s, exit {entry['exit']}, "
                  f"{len(entry.get('live', []))} live, failed sources: {entry.get('failed')}", flush=True)
            if args.out:
                args.out.write_text(json.dumps(results, indent=1), encoding="utf-8")

    print("\nvariant   seconds (each run)            median  live names (each run)")
    for label, _ in variants:
        runs = [r for r in results if r["variant"] == label]
        secs = [r["seconds"] for r in runs]
        print(f"{label:<9} {secs}  {statistics.median(secs):6.1f}  {[len(r.get('live', [])) for r in runs]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
