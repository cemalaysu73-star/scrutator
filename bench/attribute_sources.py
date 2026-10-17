#!/usr/bin/env python
"""Which source gave which names? Runs sublist3r one engine at a time and knockpy's recon services
one service at a time against ONE frozen target (default owasp.org), passive only, and writes
bench/results/<date>/attribution-<target>.json plus a short table on stdout.

This exists because the main benchmark only sees each tool's union of sources. Needs the same
benchmark venv as run_bench.py.   python bench/attribute_sources.py --date 2026-10-17
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_bench as rb  # noqa: E402

SUBLIST3R_ENGINES = ["baidu", "yahoo", "google", "bing", "ask", "netcraft", "dnsdumpster", "virustotal", "threatcrowd", "ssl", "passivedns"]

KNOCK_PROBE = r"""
import asyncio, json, sys
from knockpy.knockpy import Recon
domain = sys.argv[1]
engine = Recon(domain, timeout=3.0, max_concurrency=40)
async def go():
    import httpx
    out = {}
    async with httpx.AsyncClient(headers=engine.headers, http2=True, timeout=3.0) as client:
        for spec in engine.services():
            name, parser, url = spec.get("name"), spec.get("parser", ""), spec.get("url", "")
            try:
                _, text = await engine._fetch(client, name, url)
                out[name] = {"names": engine._parse(parser, text), "bytes": len(text or "")}
            except Exception as exc:
                out[name] = {"names": [], "error": type(exc).__name__}
    return out
print(json.dumps(asyncio.run(go())))
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--date", default="2026-10-17")
    parser.add_argument("--target", default="owasp.org", choices=list(rb.TARGETS))
    parser.add_argument("--bench-venv", type=Path, default=Path(os.environ.get("BENCH_VENV", Path.home() / "bench-venv")))
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()

    out_dir = rb.ROOT / "results" / args.date
    out_dir.mkdir(parents=True, exist_ok=True)
    work = rb.ROOT / "work"
    result: dict = {"target": args.target, "sublist3r": {}, "knockpy": {}}
    cache: dict = {}
    exe = rb.venv_exe(args.bench_venv, "sublist3r")
    for engine in SUBLIST3R_ENGINES:
        run = rb.run_cmd([str(exe), "-d", args.target, "-n", "-e", engine, "-o", str(work / f"attr-{engine}.txt")], args.timeout, work)
        out_file = work / f"attr-{engine}.txt"
        names = {l.strip() for l in out_file.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()} if out_file.exists() else set()
        names, _ = rb.normalise(names, args.target)
        errors = [l.strip() for l in run.stdout.splitlines() if "[!]" in l and "Coloring" not in l][:2]
        result["sublist3r"][engine] = {"names": sorted(names), "seconds": run.seconds, "errors": errors}
    py = rb.venv_exe(args.bench_venv, "python")
    home = work / "home"
    run = rb.run_cmd([str(py), "-c", KNOCK_PROBE, args.target], args.timeout, work, env={"USERPROFILE": str(home), "HOME": str(home)})
    try:
        result["knockpy"] = json.loads(run.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        result["knockpy"] = {"error": run.stderr[-300:]}

    everything = set()
    for section in ("sublist3r", "knockpy"):
        for info in result[section].values():
            if isinstance(info, dict):
                everything |= set(info.get("names", []))
    everything, _ = rb.normalise(everything, args.target)
    rb.resolve_many(everything, cache)
    wildcard = rb.wildcard_probe(args.target)
    live = {n for n in everything if rb.classify(n, cache, wildcard) == "live"}
    print(f"{'source':<22}{'names':>6}{'live':>6}  notes")
    for section in ("sublist3r", "knockpy"):
        for name, info in result[section].items():
            if not isinstance(info, dict):
                continue
            norm, _ = rb.normalise(info.get("names", []), args.target)
            info["live"] = len(norm & live)
            print(f"{section + ':' + name:<22}{len(norm):>6}{len(norm & live):>6}  {'; '.join(info.get('errors', [])) or info.get('error', '')}")
    (out_dir / f"attribution-{args.target}.json").write_text(json.dumps(result, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
