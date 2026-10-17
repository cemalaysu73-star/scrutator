"""Task 1 of v0.6: a scan always finishes inside its deadline, a source that keeps failing is
marked down (and the report says so), name-enumerating sources run once per apex, and
independent sources run at the same time."""

import asyncio
import time

import httpx
import pytest

from scrutator.deadline import Deadline
from scrutator.engine import Engine
from scrutator.model import Entity, EntityType, Evidence, ScopeState
from scrutator.modules.base import Module, ModuleError, Observation, SourceUnavailable
from scrutator.report.build import build_report, source_health
from scrutator.scan import run_scan
from scrutator.scope import ScopePolicy
from scrutator.store import Store

D = EntityType.DOMAIN


def dom(value):
    return Entity(type=D, value=value)


class Names(Module):
    """Returns children for an entity, like a certificate or archive source."""

    name = "names"
    accepts = frozenset({D})

    def __init__(self, mapping=None, *, apex_only=False, delay=0.0, name="names"):
        self.mapping = mapping or {}
        self.name = name
        self.apex_only = apex_only
        self.delay = delay
        self.calls = []

    async def run(self, entity, ctx):
        self.calls.append(entity.value)
        if self.delay:
            await asyncio.sleep(self.delay)
        return [
            Observation(dom(c), "has_subdomain", Evidence.create(self.name, f"{self.name} {entity.value}", c))
            for c in self.mapping.get(entity.value, [])
        ]


class Failing(Module):
    name = "flaky"
    accepts = frozenset({D})
    concurrency = 1

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)  # exception instance to raise, or None for success
        self.calls = []

    async def run(self, entity, ctx):
        self.calls.append(entity.value)
        outcome = self.outcomes.pop(0) if self.outcomes else None
        if outcome is not None:
            raise outcome
        return []


@pytest.fixture
def env():
    store = Store(":memory:")
    scope = ScopePolicy(domains=["example.com"])
    scan = store.create_scan("example.com")
    store.upsert_entity(scan, dom("example.com"), ScopeState.IN)
    return store, scope, scan


def seed_many(store, scan, n):
    for i in range(n):
        store.upsert_entity(scan, dom(f"h{i}.example.com"), ScopeState.IN)


# ---------------------------------------------------------------- circuit breaker


async def test_breaker_opens_after_n_consecutive_failures_and_skips_the_rest(env):
    store, scope, scan = env
    seed_many(store, scan, 6)
    engine = Engine(store, scope, None, breaker_threshold=3)
    flaky = Failing([httpx.ConnectTimeout("x")] * 10)
    for i in range(6):
        await engine.run_module(scan, flaky, dom(f"h{i}.example.com"))

    assert len(flaky.calls) == 3  # the other three never reached the source
    log = store.audit_log(scan)
    assert [r["event"] for r in log].count("error") == 3
    assert [r["event"] for r in log].count("breaker") == 1
    assert [r["event"] for r in log].count("skipped") == 3
    skipped = [r for r in log if r["event"] == "skipped"]
    assert all("down" in r["reason"] for r in skipped)
    health = source_health(store, scan)["flaky"]
    assert health["down"] is True and health["skipped"] == 3 and health["error"] == 3
    assert "marked down" in " ".join(health["errors"])


async def test_a_success_resets_the_count(env):
    store, scope, scan = env
    seed_many(store, scan, 6)
    engine = Engine(store, scope, None, breaker_threshold=3)
    flaky = Failing([SourceUnavailable("HTTP 503"), SourceUnavailable("HTTP 503"), None,
                     SourceUnavailable("HTTP 503"), SourceUnavailable("HTTP 503"), None])
    for i in range(6):
        await engine.run_module(scan, flaky, dom(f"h{i}.example.com"))
    assert len(flaky.calls) == 6
    assert source_health(store, scan)["flaky"]["down"] is False


async def test_ordinary_module_errors_do_not_trip_the_breaker(env):
    """A 404-style refusal for one entity says nothing about the source being down."""
    store, scope, scan = env
    seed_many(store, scan, 5)
    engine = Engine(store, scope, None, breaker_threshold=3)
    flaky = Failing([ModuleError("returned HTTP 400")] * 5)
    for i in range(5):
        await engine.run_module(scan, flaky, dom(f"h{i}.example.com"))
    assert len(flaky.calls) == 5
    assert source_health(store, scan)["flaky"]["down"] is False
    assert source_health(store, scan)["flaky"]["error"] == 5


async def test_module_timeout_counts_as_source_failure(env):
    store, scope, scan = env
    seed_many(store, scan, 4)

    class Slow(Module):
        name = "slow"
        accepts = frozenset({D})
        timeout = 0.05
        calls = 0

        async def run(self, entity, ctx):
            Slow.calls += 1
            await asyncio.sleep(5)

    engine = Engine(store, scope, None, breaker_threshold=2)
    for i in range(4):
        await engine.run_module(scan, Slow(), dom(f"h{i}.example.com"))
    assert Slow.calls == 2
    assert source_health(store, scan)["slow"]["down"] is True


async def test_breaker_is_per_source(env):
    store, scope, scan = env
    seed_many(store, scan, 4)
    engine = Engine(store, scope, None, breaker_threshold=2)
    flaky = Failing([httpx.ConnectError("x")] * 10)
    good = Names()
    for i in range(4):
        await engine.run_module(scan, flaky, dom(f"h{i}.example.com"))
        await engine.run_module(scan, good, dom(f"h{i}.example.com"))
    assert len(good.calls) == 4


async def test_breaker_threshold_zero_disables_it(env):
    store, scope, scan = env
    seed_many(store, scan, 5)
    engine = Engine(store, scope, None, breaker_threshold=0)
    flaky = Failing([httpx.ConnectTimeout("x")] * 10)
    for i in range(5):
        await engine.run_module(scan, flaky, dom(f"h{i}.example.com"))
    assert len(flaky.calls) == 5


# ---------------------------------------------------------------- deadline


async def test_deadline_cancels_in_flight_calls_and_keeps_results_so_far(env):
    store, scope, scan = env
    fast = Names({"example.com": ["a.example.com"]}, name="fast")
    hang = Names(delay=30, name="hang")
    engine = Engine(store, scope, None, deadline=Deadline(0.4))
    started = time.monotonic()
    await asyncio.gather(
        engine.run_module(scan, fast, dom("example.com")),
        engine.run_module(scan, hang, dom("example.com")),
    )
    assert time.monotonic() - started < 3
    assert "domain:a.example.com" in {s.entity.id for s in store.entities(scan)}
    log = store.audit_log(scan)
    cancelled = [r for r in log if r["event"] == "cancelled"]
    assert len(cancelled) == 1 and cancelled[0]["module"] == "hang" and cancelled[0]["reason"] == "deadline"
    # an in-flight call killed by the clock is not the source's fault: the breaker stays closed
    assert source_health(store, scan).get("hang", {}).get("down") is not True


async def test_after_the_deadline_nothing_new_starts(env):
    store, scope, scan = env
    engine = Engine(store, scope, None, deadline=Deadline(0.0))
    mod = Names()
    await engine.run_module(scan, mod, dom("example.com"))
    assert mod.calls == []
    assert store.audit_log(scan)[-1]["event"] == "skipped"
    assert store.audit_log(scan)[-1]["reason"] == "deadline"


async def test_run_scan_finishes_inside_the_deadline_and_reports_partial_coverage():
    store = Store(":memory:")
    fast = Names({"example.com": ["a.example.com", "b.example.com"]}, apex_only=True, name="fast")
    hang = Names(delay=60, apex_only=True, name="hang")
    hang.timeout = 90
    started = time.monotonic()
    scan_id, stats = await run_scan(
        dom("example.com"), ScopePolicy(domains=["example.com"]), store, None,
        modules=[fast, hang], deadline_s=0.5,
    )
    assert time.monotonic() - started < 5
    assert stats.deadline_hit is True
    report = build_report(store, scan_id)
    assert {e["value"] for e in report["entities"]} >= {"a.example.com", "b.example.com"}
    assert report["coverage"]["deadline_hit"] is True
    assert report["coverage"]["deadline_s"] == 0.5
    assert report["sources"]["hang"]["cancelled"] == 1


async def test_a_scan_that_finishes_early_does_not_claim_a_deadline():
    store = Store(":memory:")
    scan_id, stats = await run_scan(
        dom("example.com"), ScopePolicy(domains=["example.com"]), store, None,
        modules=[Names({"example.com": ["a.example.com"]})], deadline_s=30,
    )
    assert stats.deadline_hit is False
    assert build_report(store, scan_id)["coverage"]["deadline_hit"] is False


async def test_a_hung_planner_cannot_hold_the_scan_past_its_deadline():
    from llmfakes import ScriptedProvider
    from scrutator.ai.runtime import AIRuntime

    async def hang(*args, **kwargs):
        await asyncio.sleep(60)

    store = Store(":memory:")
    names = Names({"example.com": [f"h{i}.example.com" for i in range(5)]})
    ai = AIRuntime({"planner": ScriptedProvider(responder=lambda s, u, sch: {"choices": [0], "hypothesis": "x"})})
    ai.generate = lambda *a, **k: hang(*a, **k)  # type: ignore[method-assign]
    started = time.monotonic()
    scan_id, stats = await run_scan(
        dom("example.com"), ScopePolicy(domains=["example.com"]), store, None,
        modules=[names], ai=ai, max_steps=3, deadline_s=0.5,
    )
    assert time.monotonic() - started < 5
    assert stats.deadline_hit is True
    assert store.entities(scan_id)  # the seed and whatever was found are still there


# ---------------------------------------------------------------- enumerators run once per apex


async def test_enumerating_sources_run_on_the_apex_only():
    store = Store(":memory:")
    enum = Names({"example.com": ["a.example.com", "b.example.com"]}, apex_only=True, name="enum")
    plain = Names(name="plain")
    await run_scan(
        dom("example.com"), ScopePolicy(domains=["example.com"]), store, None, modules=[enum, plain]
    )
    assert enum.calls == ["example.com"]
    assert sorted(plain.calls) == ["a.example.com", "b.example.com", "example.com"]


async def test_the_seed_counts_as_an_apex_even_when_scope_is_wider():
    store = Store(":memory:")
    enum = Names({"dev.example.com": ["x.dev.example.com"]}, apex_only=True, name="enum")
    await run_scan(
        dom("dev.example.com"), ScopePolicy(domains=["example.com"]), store, None, modules=[enum]
    )
    assert enum.calls == ["dev.example.com"]


async def test_cheap_resolving_runs_before_other_lookups_when_budget_is_short():
    """The step budget is spent on resolving names before anything else."""
    store = Store(":memory:")
    late, early = Names(name="aaa"), Names(name="zzz")
    late.priority, early.priority = 60, 10  # alphabetical order alone would run "aaa" first
    await run_scan(
        dom("example.com"), ScopePolicy(domains=["example.com"]), store, None,
        modules=[late, early], max_steps=1,
    )
    assert early.calls == ["example.com"] and late.calls == []


# ---------------------------------------------------------------- independent sources overlap


async def test_independent_sources_run_at_the_same_time():
    store = Store(":memory:")
    mods = [Names(delay=0.4, apex_only=True, name=f"src{i}") for i in range(4)]
    started = time.monotonic()
    await run_scan(dom("example.com"), ScopePolicy(domains=["example.com"]), store, None, modules=mods)
    assert time.monotonic() - started < 1.0  # sequential would be 1.6 s


async def test_sources_sharing_a_host_share_one_limit(env):
    store, scope, scan = env
    active = 0
    peak = 0

    class Shared(Module):
        accepts = frozenset({D})
        concurrency = 1
        rate_group = "ripestat"

        async def run(self, entity, ctx):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.05)
            active -= 1
            return []

    class A(Shared):
        name = "a"

    class B(Shared):
        name = "b"

    engine = Engine(store, scope, None)
    await asyncio.gather(
        engine.run_module(scan, A(), dom("example.com")), engine.run_module(scan, B(), dom("example.com"))
    )
    assert peak == 1


def test_registration_data_and_name_sources_are_asked_once_per_apex():
    from scrutator.modules.commoncrawl import CommonCrawl
    from scrutator.modules.crtsh import CrtSh
    from scrutator.modules.dns import Dns
    from scrutator.modules.rdap import Rdap
    from scrutator.modules.wayback import Wayback

    engine = Engine(Store(":memory:"), ScopePolicy(domains=["example.com"]), None)
    for module in (CrtSh(), Wayback(), CommonCrawl(), Rdap()):
        assert engine.applies(module, dom("example.com")), module.name
        assert not engine.applies(module, dom("www.example.com")), module.name
    assert engine.applies(Dns(), dom("www.example.com"))
    # an address is not a name: rdap still looks up the network owner of every address
    assert engine.applies(Rdap(), Entity(type=EntityType.IP, value="192.0.2.1"))


def test_the_default_step_budget_covers_a_large_name_list():
    from scrutator.ai.config import AIConfig

    assert AIConfig().max_steps == 1000
