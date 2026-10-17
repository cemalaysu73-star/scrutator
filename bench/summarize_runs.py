#!/usr/bin/env python
"""Side-by-side of several benchmark runs (run-to-run variance), from their results.json files.

    python bench/summarize_runs.py 2026-10-17 2026-10-17-run2 2026-10-17-run3 > variance.md

Public sources (crt.sh above all) answer differently from one run to the next, so one run is an
anecdote. This prints, per target and tool, found / live / recall / seconds for each run, and the
sources Scrutator reported as failed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "results"


def main(argv: list[str]) -> int:
    runs = argv or ["2026-10-17"]
    data = {run: json.loads((ROOT / run / "results.json").read_text(encoding="utf-8")) for run in runs}
    targets = [t["target"] for t in data[runs[0]]["targets"]]
    print("| Target | Tool | " + " | ".join(f"run {i + 1} (found / live / recall / s)" for i in range(len(runs))) + " |")
    print("|---|---|" + "---|" * len(runs))
    for target in targets:
        tools = [r["tool"] for r in next(t for t in data[runs[0]]["targets"] if t["target"] == target)["rows"]]
        for tool in tools:
            cells = []
            for run in runs:
                row = next(r for t in data[run]["targets"] if t["target"] == target for r in t["rows"] if r["tool"] == tool)
                cells.append(f"{row['found']} / {row['live']} / {row['recall']} / {row['seconds']:.0f}" + ("" if row["status"] == "ok" else f" ({row['status']})"))
            print(f"| {target} | {tool} | " + " | ".join(cells) + " |")
    print()
    print("Scrutator sources that failed after retries:")
    print()
    print("| Target | " + " | ".join(f"run {i + 1}" for i in range(len(runs))) + " |")
    print("|---|" + "---|" * len(runs))
    for target in targets:
        cells = []
        for run in runs:
            path = ROOT / run / target / "scrutator.result.json"
            extra = json.loads(path.read_text(encoding="utf-8")).get("extra", {}) if path.exists() else {}
            cells.append(", ".join(extra.get("sources_failed", [])) or ("none" if extra else "no report (timeout)"))
        print(f"| {target} | " + " | ".join(cells) + " |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
