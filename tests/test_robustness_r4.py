"""R4 A6: interrupted, deadline-cut, parallel and very wide scans leave a consistent database and a verifiable bundle,
and a bad or busy database is a clear message, never a traceback."""

import asyncio
import sqlite3
import subprocess
import sys
import threading
from contextlib import asynccontextmanager

import httpx
import pytest
import respx
from typer.testing import CliRunner

from scrutator import cli
from scrutator.bundle.keys import generate_keypair, load_private_key, private_key_path
from scrutator.bundle.verify import verify_bundle
from scrutator.bundle.writer import create_bundle
from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules.base import Module, ModuleContext, Observation
from scrutator.modules.registry import load_builtin_modules
from scrutator.report import build_report
from scrutator.resolver import DnsAnswer
from scrutator.scan import run_scan
from scrutator.scope import ScopePolicy
from scrutator.store import Store, StoreError

SEED = Entity(type=EntityType.DOMAIN, value="example.com")
runner = CliRunner()


class Resolver:
    async def query(self, name, rtype):
        if rtype == "A" and name in ("example.com", "www.example.com", "a.example.com"):
            return DnsAnswer("answer", ("192.0.2.1",))
        return DnsAnswer("nxdomain")

    async def lookup(self, name, rtype):
        return list((await self.query(name, rtype)).records)


class Lister(Module):
    """A source that names `count` hosts under the apex in one answer."""

    name = "lister"
    accepts = frozenset({EntityType.DOMAIN})
    apex_only = True

    def __init__(self, count=3, delay=0.0):
        self.count, self.delay = count, delay

    async def run(self, entity, ctx):
        if self.delay:
            await asyncio.sleep(self.delay)
        evidence = Evidence.create("lister", f"GET https://lister.test/{entity.value}", "names")
        return [Observation(Entity(type=EntityType.DOMAIN, value=f"h{i}.{entity.value}"), "has_subdomain", evidence) for i in range(self.count)]


def key(tmp_path):
    generate_keypair(tmp_path / "keys")
    return load_private_key(private_key_path(tmp_path / "keys"))


def dns_module():
    return next(m for m in load_builtin_modules() if m.name == "dns")


# ------------------------------------------------------------------------------------------ Ctrl-C and the deadline


def test_ctrl_c_in_the_middle_of_a_write_leaves_a_consistent_database_and_a_bundle_that_verifies(tmp_path, monkeypatch):
    calls = {"edges": 0}
    real_add_edge = Store.add_edge

    def interrupting_add_edge(self, *args, **kwargs):
        calls["edges"] += 1
        if calls["edges"] == 5:  # inside the batch of the lister's lookup, after some of its rows were written
            raise KeyboardInterrupt
        return real_add_edge(self, *args, **kwargs)

    monkeypatch.setattr(Store, "add_edge", interrupting_add_edge)

    @asynccontextmanager
    async def context():
        async with httpx.AsyncClient() as http:
            yield ModuleContext(http=http, resolver=Resolver())

    async def scan_with_modules(seed, scope, store, ctx, **kwargs):
        return await run_scan(seed, scope, store, ctx, modules=[dns_module(), Lister(count=10)], max_steps=50, deadline=kwargs.get("deadline"))

    monkeypatch.setattr(cli, "open_context", context)
    monkeypatch.setattr(cli, "run_scan", scan_with_modules)
    key(tmp_path)
    out = tmp_path / "o"
    result = runner.invoke(cli.app, ["scan", "example.com", "--out", str(out), "--ai", "off", "--bundle", "--key-dir", str(tmp_path / "keys")])
    assert result.exit_code == 0, result.output
    assert "Interrupted" in result.output
    store = Store(out / "scrutator.db")
    assert store.verify_audit(1)
    edges = store.edges(1)
    # the interrupted lookup's batch was rolled back as a whole: none of its names, none of its rows
    assert not any(e.dst.startswith("domain:h") for e in edges)
    assert all(store.get_evidence(i) is not None for e in edges for i in e.evidence_ids)
    store.close()
    checked = verify_bundle(out / "proof.scrutator")
    assert checked.ok, [c for c in checked.checks if not c.ok]


async def test_a_scan_cut_by_its_deadline_yields_a_verifiable_partial_bundle(tmp_path):
    store = Store(tmp_path / "s.db")
    async with httpx.AsyncClient() as http:
        scan_id, stats = await run_scan(
            SEED, ScopePolicy(domains=["example.com"]), store, ModuleContext(http=http, resolver=Resolver()),
            modules=[dns_module(), Lister(count=3, delay=5.0)], max_steps=50, deadline_s=0.5,
        )
    assert stats.deadline_hit
    report = build_report(store, scan_id)
    assert report["coverage"]["deadline_hit"] is True
    create_bundle(store, scan_id, key(tmp_path), tmp_path / "p.scrutator")
    store.close()
    assert verify_bundle(tmp_path / "p.scrutator").ok


# ------------------------------------------------------------------------------------------ two scans, one database


def test_two_scans_in_parallel_on_one_database_both_finish_and_both_verify(tmp_path):
    db = tmp_path / "shared.db"
    Store(db).close()
    results, errors = {}, []
    private = key(tmp_path)

    def one(seed: str):
        try:
            store = Store(db)
            entity = Entity(type=EntityType.DOMAIN, value=seed)

            async def go():
                async with httpx.AsyncClient() as http:
                    return await run_scan(entity, ScopePolicy(domains=[seed]), store, ModuleContext(http=http, resolver=Resolver()),
                                          modules=[dns_module(), Lister(count=300)], max_steps=1000)

            scan_id, _ = asyncio.run(go())
            create_bundle(store, scan_id, private, tmp_path / f"{seed}.scrutator")
            results[seed] = (scan_id, store.verify_audit(scan_id), store.entity_count(scan_id))
            store.close()
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))

    threads = [threading.Thread(target=one, args=(seed,)) for seed in ("example.com", "example.net")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(120)
    assert errors == [] and len(results) == 2
    assert {r[1] for r in results.values()} == {True} and all(r[2] > 300 for r in results.values())
    assert len({r[0] for r in results.values()}) == 2
    for seed in results:
        assert verify_bundle(tmp_path / f"{seed}.scrutator").ok


# ------------------------------------------------------------------------------------------ very wide scans


async def test_the_entity_cap_is_hard_and_what_it_dropped_is_reported(tmp_path):
    store = Store(tmp_path / "s.db")
    async with httpx.AsyncClient() as http:
        scan_id, _ = await run_scan(
            SEED, ScopePolicy(domains=["example.com"]), store, ModuleContext(http=http, resolver=Resolver()),
            modules=[dns_module(), Lister(count=3000)], max_steps=10_000, max_entities=500,
        )
    assert store.entity_count(scan_id) <= 500
    report = build_report(store, scan_id)
    capped = report["coverage"]["entity_cap"]
    assert capped["cap"] == 500 and capped["dropped"] >= 2500
    assert store.verify_audit(scan_id)
    create_bundle(store, scan_id, key(tmp_path), tmp_path / "p.scrutator")
    store.close()
    assert verify_bundle(tmp_path / "p.scrutator").ok


async def test_a_scan_under_the_cap_reports_no_cap(tmp_path):
    store = Store(":memory:")
    async with httpx.AsyncClient() as http:
        scan_id, _ = await run_scan(SEED, ScopePolicy(domains=["example.com"]), store, ModuleContext(http=http, resolver=Resolver()),
                                    modules=[Lister(count=5)], max_steps=100)
    assert "entity_cap" not in build_report(store, scan_id)["coverage"]


def test_the_cli_says_when_the_cap_was_reached(tmp_path, monkeypatch):
    @asynccontextmanager
    async def context():
        async with httpx.AsyncClient() as http:
            yield ModuleContext(http=http, resolver=Resolver())

    async def scan_with_modules(seed, scope, store, ctx, **kwargs):
        return await run_scan(seed, scope, store, ctx, modules=[Lister(count=50)], max_steps=100, max_entities=kwargs["max_entities"])

    monkeypatch.setattr(cli, "open_context", context)
    monkeypatch.setattr(cli, "run_scan", scan_with_modules)
    result = runner.invoke(cli.app, ["scan", "example.com", "--out", str(tmp_path / "o"), "--ai", "off", "--max-entities", "20"])
    assert result.exit_code == 0, result.output
    assert "Entity cap of 20 reached" in result.output and "--max-entities" in result.output


# ------------------------------------------------------------------------------------------ bad and busy databases


def run_cli(*args, cwd=None):
    return subprocess.run([sys.executable, "-m", "scrutator", *args], capture_output=True, text=True, timeout=120, cwd=cwd)


def test_a_file_that_is_not_a_database_is_a_clear_usage_error(tmp_path):
    bad = tmp_path / "bad.db"
    bad.write_bytes(b"this is not sqlite at all, but long enough to look like a header....." * 20)
    with pytest.raises(StoreError, match="not a Scrutator database"):
        Store(bad)
    for args in (["risk", "--db", str(bad)], ["sources", "--db", str(bad)], ["candidates", "--db", str(bad)]):
        done = run_cli(*args)
        assert done.returncode == 2, (args, done.stdout, done.stderr)
        assert "Traceback" not in done.stderr and "bad.db" in done.stderr and "not a Scrutator database" in done.stderr


def test_a_database_locked_by_another_process_is_a_clear_usage_error(tmp_path, monkeypatch):
    db = tmp_path / "busy.db"
    Store(db).close()
    holder = sqlite3.connect(db)
    holder.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(StoreError, match="another process"):
            Store(db, timeout=0.2)
    finally:
        holder.rollback()
        holder.close()


def test_a_damaged_database_is_a_clear_usage_error(tmp_path):
    db = tmp_path / "damaged.db"
    store = Store(db)
    scan = store.create_scan("example.com")
    for i in range(300):
        store.add_evidence(Evidence.create("x", f"GET https://x.test/{i}", "y" * 500))
    store.close()
    data = bytearray(db.read_bytes())
    for offset in range(4096, len(data), 4096):  # every page after the first: garbage
        data[offset : offset + 64] = b"\xff" * 64
    db.write_bytes(bytes(data))
    done = run_cli("risk", str(scan), "--db", str(db))
    assert done.returncode == 2 and "Traceback" not in done.stderr and "damaged.db" in done.stderr, (done.stdout, done.stderr)


