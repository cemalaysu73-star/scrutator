#!/usr/bin/env python
"""Where do the seconds of a Scrutator scan go?  One live scan with timers around every stage.

    python bench/profile_scan.py owasp.org [--out DIR] [--json FILE]

It runs the same collection as `scrutator scan <target> --ai off --bundle` (the benchmark's command),
and measures, without changing what is collected:

  * wall time of each phase: collection (run_scan), report build, JSON, HTML, signed bundle;
  * per source (module): calls, summed seconds inside `Module.run`, the slowest call, and the window in
    which it was active;
  * every physical HTTP request (retries and redirect hops included) by host: count, 429/5xx answers,
    summed and slowest seconds - this separates a slow service from our own retry back-off;
  * every DNS query that went out: count, median, 95th percentile, slowest; and how many questions the
    scan's own memory answered instead;
  * the critical path: the lookups that finished last (the scan ends when the last one does);
  * time inside the store (SQLite commits), which blocks the event loop.

Only the benchmark targets and example.com / 1.1.1.1 are ever queried. Passive GETs and DNS lookups only.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

ALLOWED = {"zonetransfer.me", "example.com", "nmap.org", "owasp.org", "1.1.1.1"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target")
    parser.add_argument("--out", type=Path, default=None, help="directory for the report (default: a temporary one)")
    parser.add_argument("--json", type=Path, default=None, help="also write the measurements as JSON")
    parser.add_argument("--deadline", type=float, default=600.0)
    args = parser.parse_args()
    if args.target not in ALLOWED:
        print(f"refusing {args.target!r}: only {sorted(ALLOWED)} may be queried", file=sys.stderr)
        return 2

    import httpx

    from scrutator.bundle.keys import generate_keypair, load_private_key, private_key_path
    from scrutator.bundle.writer import create_bundle
    from scrutator.context import open_context
    from scrutator.deadline import Deadline
    from scrutator.model import Entity, EntityType
    from scrutator.modules.registry import load_builtin_modules
    from scrutator.report import build_report, render_html, render_json
    from scrutator.resolver import DnsResolver
    from scrutator.scan import run_scan
    from scrutator.scope import ScopePolicy
    from scrutator.store import Store

    t0 = time.perf_counter()
    calls: list[dict] = []  # one per Module.run
    dns_times: list[float] = []
    dns_keys: list[tuple[str, str]] = []
    wire: list[dict] = []  # one per physical HTTP request
    store_time = defaultdict(lambda: [0, 0.0])  # method -> [calls, seconds]

    modules = load_builtin_modules()
    for module in modules:
        original = module.run

        def timed(entity, ctx, _orig=original, _name=module.name):
            async def go():
                start = time.perf_counter()
                try:
                    return await _orig(entity, ctx)
                finally:
                    calls.append({"module": _name, "entity": entity.value, "start": start - t0, "end": time.perf_counter() - t0})

            return go()

        module.run = timed  # type: ignore[method-assign]

    # DNS: the query that goes out (v0.7 splits it from the scan's memory; v0.6 has only `query`)
    attr = "_ask" if hasattr(DnsResolver, "_ask") else "query"
    original_query = getattr(DnsResolver, attr)

    async def timed_query(self, name, rtype):
        dns_keys.append((name, rtype))
        start = time.perf_counter()
        try:
            return await original_query(self, name, rtype)
        finally:
            dns_times.append(time.perf_counter() - start)

    setattr(DnsResolver, attr, timed_query)

    # HTTP: every request that reaches the network, under the retrying transport
    original_inner = httpx.AsyncHTTPTransport.handle_async_request

    async def timed_inner(self, request):
        start = time.perf_counter()
        status = "error"
        try:
            response = await original_inner(self, request)
            status = response.status_code
            return response
        finally:
            wire.append({"host": request.url.host, "path": request.url.path[:48], "status": status, "start": start - t0, "seconds": time.perf_counter() - start})

    httpx.AsyncHTTPTransport.handle_async_request = timed_inner  # type: ignore[method-assign]

    for name in ("add_evidence", "add_edge", "upsert_entity", "append_audit", "add_scan_evidence", "entities", "edges", "scope_state", "audit_log"):
        original_method = getattr(Store, name)

        def wrap(method, label):
            def inner(self, *a, **kw):
                start = time.perf_counter()
                try:
                    return method(self, *a, **kw)
                finally:
                    entry = store_time[label]
                    entry[0] += 1
                    entry[1] += time.perf_counter() - start

            return inner

        setattr(Store, name, wrap(original_method, name))

    out = args.out or Path(tempfile.mkdtemp(prefix="scrutator-profile-"))
    out.mkdir(parents=True, exist_ok=True)
    phases: dict[str, float] = {}
    memo: dict = {}

    async def collect():
        store = Store(out / "scrutator.db")
        seed = Entity(type=EntityType.DOMAIN, value=args.target)
        scope = ScopePolicy(domains=[args.target])
        start = time.perf_counter()
        async with open_context() as ctx:
            memo["resolver"] = ctx.resolver
            scan_id, stats = await run_scan(seed, scope, store, ctx, ai=None, max_steps=1000, deadline=Deadline(args.deadline), modules=modules)
            memo["cache"] = {k: len(v) for k, v in getattr(ctx, "cache", {}).items() if hasattr(v, "__len__")}
        phases["collect"] = time.perf_counter() - start
        return store, scan_id, stats

    store, scan_id, stats = asyncio.run(collect())

    start = time.perf_counter()
    report = build_report(store, scan_id)
    phases["build_report"] = time.perf_counter() - start
    start = time.perf_counter()
    (out / "report.json").write_text(render_json(report), encoding="utf-8")
    phases["write_json"] = time.perf_counter() - start
    start = time.perf_counter()
    (out / "report.html").write_text(render_html(report), encoding="utf-8")
    phases["write_html"] = time.perf_counter() - start
    key_dir = out / "keys"
    generate_keypair(key_dir)
    start = time.perf_counter()
    create_bundle(store, scan_id, load_private_key(private_key_path(key_dir)), out / "proof.scrutator")
    phases["bundle"] = time.perf_counter() - start
    total = time.perf_counter() - t0

    per_module: dict[str, dict] = {}
    for call in calls:
        entry = per_module.setdefault(call["module"], {"calls": 0, "seconds": 0.0, "slowest": 0.0, "slowest_entity": "", "first_start": 1e9, "last_end": 0.0})
        length = call["end"] - call["start"]
        entry["calls"] += 1
        entry["seconds"] += length
        entry["first_start"] = min(entry["first_start"], call["start"])
        entry["last_end"] = max(entry["last_end"], call["end"])
        if length > entry["slowest"]:
            entry["slowest"], entry["slowest_entity"] = length, call["entity"]

    per_host: dict[str, dict] = {}
    for item in wire:
        entry = per_host.setdefault(item["host"], {"requests": 0, "retried": 0, "seconds": 0.0, "slowest": 0.0})
        entry["requests"] += 1
        entry["retried"] += 1 if item["status"] in (429, 500, 502, 503, 504, "error") else 0
        entry["seconds"] += item["seconds"]
        entry["slowest"] = max(entry["slowest"], item["seconds"])

    hits = getattr(memo.get("resolver"), "cache_hits", 0)
    print(f"\nScrutator profile of {args.target}: total {total:.1f} s (collection {phases['collect']:.1f} s)")
    print(f"  entities {report['summary']['entities']}, edges {report['summary']['edges']}, evidence {len(report['evidence'])}, "
          f"module runs {stats.modules_run}, depth {stats.rounds}, headline: {report['summary']['headline']}")
    print("\nPhases (s):")
    for name, seconds in phases.items():
        print(f"  {name:<14}{seconds:8.2f}")
    print("\nPer source: calls, summed seconds in Module.run, slowest call (entity), window in which it was active (s)")
    for name, entry in sorted(per_module.items(), key=lambda kv: -kv[1]["last_end"]):
        print(f"  {name:<16}{entry['calls']:5d} calls {entry['seconds']:8.1f} s  slowest {entry['slowest']:6.1f} s ({entry['slowest_entity'][:30]})"
              f"  window {entry['first_start']:6.1f}..{entry['last_end']:6.1f}")
    print("\nPhysical HTTP requests by host (retries and redirect hops count): requests, retried-status/errors, summed s, slowest s")
    for host, entry in sorted(per_host.items(), key=lambda kv: -kv[1]["seconds"]):
        print(f"  {host:<28}{entry['requests']:5d} req {entry['retried']:4d} retried/err {entry['seconds']:8.1f} s  slowest {entry['slowest']:6.1f} s")
    statuses = defaultdict(int)
    for item in wire:
        statuses[item["status"]] += 1
    print(f"  statuses: {dict(statuses)}")
    if dns_times:
        ordered = sorted(dns_times)
        p95 = ordered[max(0, int(len(ordered) * 0.95) - 1)]
        print(f"\nDNS queries on the wire: {len(dns_times)}, median {statistics.median(dns_times) * 1000:.0f} ms, "
              f"p95 {p95 * 1000:.0f} ms, slowest {max(dns_times):.1f} s; repeats of an earlier (name, type): "
              f"{len(dns_keys) - len(set(dns_keys))}; answered from the scan's memory instead: {hits}")
    cache = memo.get("cache") or {}
    if cache:
        print(f"Module memory at the end of the scan: {cache}")
    print("\nCritical path (the lookups that finished last):")
    for call in sorted(calls, key=lambda c: -c["end"])[:6]:
        print(f"  {call['end']:6.1f} s  {call['module']:<12} {call['entity'][:40]:<40} ran {call['end'] - call['start']:5.1f} s (started {call['start']:5.1f})")
    print("\nStore (SQLite) time inside the scan (blocks the event loop): calls, seconds")
    for label, (n, seconds) in sorted(store_time.items(), key=lambda kv: -kv[1][1])[:5]:
        print(f"  {label:<18}{n:7d} calls {seconds:8.2f} s")
    print(f"  total {sum(v[1] for v in store_time.values()):.2f} s")

    if args.json:
        args.json.write_text(json.dumps({
            "target": args.target, "total": total, "phases": phases, "modules": per_module, "hosts": per_host,
            "dns": {"on_the_wire": len(dns_times), "memory_hits": hits, "repeats": len(dns_keys) - len(set(dns_keys))},
            "store_seconds": sum(v[1] for v in store_time.values()), "headline": report["summary"]["headline"],
            "evidence": len(report["evidence"]), "calls": calls, "wire": wire,
        }, indent=1, default=str), encoding="utf-8")
    print(f"\nOutput in {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
