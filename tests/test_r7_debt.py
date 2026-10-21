"""R7 T7: the debt R6 left.

- crt.sh's database is the one connection that is not HTTP. It passes an egress check of its own (`egress.check_tcp`,
  one allowed endpoint, fixed in code); this file fails if the endpoint changes or if pgwire could reach another one.
- A source that only lists names (an aggregator) can never use up the entity cap before DNS has resolved the names that
  a certificate or DNS vouches for: a fifth of the cap is kept for them, and the cap is reported with who filled it.
"""

import asyncio
import time

import httpx
import pytest

from scrutator import egress, pgwire
from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules import crtsh
from scrutator.modules.base import Module, ModuleContext, Observation
from scrutator.modules.registry import load_builtin_modules
from scrutator.report import build_report
from scrutator.resolver import DnsAnswer
from scrutator.scan import run_scan
from scrutator.scope import ScopePolicy
from scrutator.store import Store

SEED = Entity(type=EntityType.DOMAIN, value="example.com")


# ------------------------------------------------------------------------------------------ crt.sh database egress


def test_the_only_raw_tcp_endpoint_is_crt_sh_5432_and_the_crtsh_module_uses_exactly_it():
    # if the host or port of the database fallback changes, this must be changed on purpose, with the docs
    assert egress.TCP_ENDPOINTS == frozenset({("crt.sh", 5432)})
    assert (crtsh.DB_HOST, crtsh.DB_PORT) in egress.TCP_ENDPOINTS
    assert crtsh.db_request("example.com").startswith("PGSQL crt.sh:5432/")


@pytest.mark.parametrize("host,port", [("crt.sh", 5433), ("evil.example", 5432), ("127.0.0.1", 5432), ("CRT.SH.", 1)])
async def test_pgwire_refuses_any_other_endpoint_before_connecting(monkeypatch, host, port):
    async def no_connection(*args, **kwargs):
        raise AssertionError("a connection was opened")

    monkeypatch.setattr(asyncio, "open_connection", no_connection)
    with pytest.raises(egress.EgressDenied, match="not an allowed TCP endpoint"):
        await pgwire.query(host, "SELECT 1", port=port, timeout=2)


def test_the_allowed_endpoint_passes_the_check_case_insensitively():
    egress.check_tcp("crt.sh", 5432)
    egress.check_tcp("CRT.SH.", 5432)


# ------------------------------------------------------------------------------------------ the entity budget


class Resolver:
    """example.com and www.example.com exist; every other name is NXDOMAIN."""

    async def query(self, name, rtype):
        if rtype == "A" and name in ("example.com", "www.example.com"):
            return DnsAnswer("answer", ("192.0.2.1",))
        return DnsAnswer("nxdomain")

    async def lookup(self, name, rtype):
        return list((await self.query(name, rtype)).records)


class Junk(Module):
    """An aggregator that answers 20,000 names that do not exist, in one answer (IP.THC.ORG gave ~5,000 in R6)."""

    name = "junk"
    accepts = frozenset({EntityType.DOMAIN})
    apex_only = True

    async def run(self, entity, ctx):
        evidence = Evidence.create("junk", f"GET https://junk.test/{entity.value}", "a list")
        return [Observation(Entity(type=EntityType.DOMAIN, value=f"j{i}.{entity.value}"), "has_subdomain", evidence) for i in range(20_000)]


class Certs(Module):
    """A certificate source (name weight 3) that answers after the aggregator and names the one real host."""

    name = "certs"
    name_weight = 3
    accepts = frozenset({EntityType.DOMAIN})
    apex_only = True

    async def run(self, entity, ctx):
        await asyncio.sleep(0.05)  # the aggregator's 20,000 names are recorded first
        evidence = Evidence.create("certs", f"GET https://certs.test/{entity.value}", "www." + entity.value)
        return [Observation(Entity(type=EntityType.DOMAIN, value="www." + entity.value), "has_subdomain", evidence)]


async def test_twenty_thousand_junk_names_cannot_starve_dns_and_the_cap_is_reported_honestly(tmp_path):
    dns = next(m for m in load_builtin_modules() if m.name == "dns")
    store = Store(tmp_path / "s.db")
    started = time.monotonic()
    async with httpx.AsyncClient() as http:
        scan_id, stats = await run_scan(
            SEED, ScopePolicy(domains=["example.com"]), store, ModuleContext(http=http, resolver=Resolver()),
            modules=[Junk(), Certs(), dns], max_steps=20_000, max_entities=1000,  # 800 junk names get DNS; the default 5,000 is the same rule, 5x slower
        )
    report = build_report(store, scan_id)
    assert store.entity_count(scan_id) <= 1000
    names = {row["name"]: row for row in report["names"]}
    assert names["www.example.com"]["state"] == "live" and names["www.example.com"]["tier"] == "verified"
    assert names["example.com"]["state"] == "live"
    capped = report["coverage"]["entity_cap"]
    assert capped["cap"] == 1000 and capped["list_sources_limit"] == 800
    assert set(capped["dropped_by_source"]) == {"junk"}  # only the aggregator lost names
    assert capped["dropped"] == capped["dropped_by_source"]["junk"] >= 19_000
    assert stats.steps_exhausted is False
    assert time.monotonic() - started < 120


async def test_the_best_vouched_names_get_a_short_step_budget_first(tmp_path):
    dns = next(m for m in load_builtin_modules() if m.name == "dns")
    store = Store(tmp_path / "s.db")
    async with httpx.AsyncClient() as http:
        scan_id, stats = await run_scan(
            SEED, ScopePolicy(domains=["example.com"]), store, ModuleContext(http=http, resolver=Resolver()),
            modules=[Junk(), Certs(), dns], max_steps=60,  # far fewer steps than names: only some names get DNS
        )
    assert stats.steps_exhausted is True
    names = {row["name"]: row for row in build_report(store, scan_id)["names"]}
    assert names["www.example.com"]["state"] == "live"  # vouched by a certificate: resolved before the junk
