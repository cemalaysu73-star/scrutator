"""How a scan behaves when one source names tens of thousands of hosts (R4 A6).

Offline: a fake crt.sh answer with N names under example.com, a fake resolver (every name NXDOMAIN except a few),
the real engine, store, report builder, HTML renderer and bundle writer. Prints wall time and peak traced Python
memory per phase, and how many names were kept.

    python bench/profile_wide.py 50000
    python bench/profile_wide.py 50000 --max-entities 60000
"""

import argparse
import asyncio
import json
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

import httpx
import respx

from scrutator.bundle.keys import generate_keypair, load_private_key, private_key_path
from scrutator.bundle.verify import verify_bundle
from scrutator.bundle.writer import create_bundle
from scrutator.model import Entity, EntityType
from scrutator.modules.base import ModuleContext
from scrutator.modules.registry import load_builtin_modules
from scrutator.report import build_report, render_html, render_json
from scrutator.resolver import DnsAnswer
from scrutator.scan import run_scan
from scrutator.scope import ScopePolicy
from scrutator.store import Store


class Resolver:
    """NXDOMAIN for everything but the apex and www."""

    async def query(self, name, rtype):
        if name in ("example.com", "www.example.com") and rtype == "A":
            return DnsAnswer("answer", ("192.0.2.1",))
        return DnsAnswer("nxdomain")

    async def lookup(self, name, rtype):
        return list((await self.query(name, rtype)).records)


def phase(label, started, rows):
    current, peak = tracemalloc.get_traced_memory()
    rows.append((label, time.perf_counter() - started, peak / 2**20))
    tracemalloc.reset_peak()


async def main(n: int, max_entities: int, work: Path) -> list:
    rows: list = []
    names = [{"name_value": f"host{i}.example.com", "not_after": "2020-01-01T00:00:00"} for i in range(n)]
    store = Store(work / "wide.db")
    modules = [m for m in load_builtin_modules() if m.name in {"crtsh", "dns"}]
    tracemalloc.start()
    started = time.perf_counter()
    async with httpx.AsyncClient() as http:
        with respx.mock(assert_all_called=False) as router:
            router.get(url__regex=r"https://crt\.sh/.*").mock(return_value=httpx.Response(200, json=names))
            scan_id, stats = await run_scan(
                Entity(type=EntityType.DOMAIN, value="example.com"), ScopePolicy(domains=["example.com"]), store,
                ModuleContext(http=http, resolver=Resolver()), modules=modules, max_steps=10**6, max_entities=max_entities,
            )
    phase("collect", started, rows)
    started = time.perf_counter()
    report = build_report(store, scan_id)
    phase("build report", started, rows)
    started = time.perf_counter()
    html = render_html(report)
    data = render_json(report)
    phase("render json+html", started, rows)
    started = time.perf_counter()
    generate_keypair(work / "keys")
    create_bundle(store, scan_id, load_private_key(private_key_path(work / "keys")), work / "wide.scrutator")
    phase("bundle", started, rows)
    started = time.perf_counter()
    ok = verify_bundle(work / "wide.scrutator").ok
    phase("verify", started, rows)
    tracemalloc.stop()
    rows.append(("entities", store.entity_count(scan_id), None))
    rows.append(("modules run", stats.modules_run, None))
    rows.append(("report MB / html MB", len(data) / 2**20, len(html) / 2**20))
    rows.append(("bundle MB / verify ok", (work / "wide.scrutator").stat().st_size / 2**20, ok))
    store.close()
    return rows


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("n", type=int)
    parser.add_argument("--max-entities", type=int, default=5000)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        for label, a, b in asyncio.run(main(args.n, args.max_entities, Path(tmp))):
            print(f"{label:<24} {a:>10.2f}  {'' if b is None else (f'{b:.1f}' if isinstance(b, float) else b)}")
    sys.exit(0)
