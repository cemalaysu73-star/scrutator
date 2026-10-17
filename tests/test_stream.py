"""v0.7 task 2: without a planner the agent does not run in barrier rounds. A lookup is started the moment
the entity it is about is known, so resolving the names a fast source lists does not wait for the slowest
source in the same round."""

import asyncio
import time

import pytest
from llmfakes import ScriptedProvider

from scrutator.agent.runner import run_agent
from scrutator.ai.runtime import AIRuntime
from scrutator.deadline import Deadline
from scrutator.engine import Engine
from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules.base import Module, Observation
from scrutator.scope import ScopePolicy
from scrutator.store import Store

D = EntityType.DOMAIN


def dom(value):
    return Entity(type=D, value=value)


class Lister(Module):
    """A source that lists names under the apex, after `delay` seconds."""

    accepts = frozenset({D})
    apex_only = True
    priority = 0

    def __init__(self, name, names, delay=0.0):
        self.name, self.names, self.delay = name, names, delay
        self.finished_at = None

    async def run(self, entity, ctx):
        await asyncio.sleep(self.delay)
        self.finished_at = time.monotonic()
        return [
            Observation(dom(n), "has_subdomain", Evidence.create(self.name, f"{self.name} {entity.value}", n))
            for n in self.names
        ]


class Resolve(Module):
    """A lookup per name; records when each started."""

    name = "resolve"
    accepts = frozenset({D})
    priority = 10
    concurrency = 50

    def __init__(self, children=None):
        self.started = {}
        self.children = children or {}

    async def run(self, entity, ctx):
        self.started[entity.value] = time.monotonic()
        await asyncio.sleep(0.01)
        return [
            Observation(dom(c), "has_subdomain", Evidence.create("resolve", f"resolve {entity.value}", c))
            for c in self.children.get(entity.value, [])
        ]


def make():
    store = Store(":memory:")
    engine = Engine(store, ScopePolicy(domains=["example.com"]), ctx=None)
    return store, engine, store.create_scan("example.com")


async def test_names_from_a_fast_source_are_resolved_while_a_slow_source_is_still_waiting():
    store, engine, scan = make()
    fast, slow = Lister("fast", ["a.example.com", "b.example.com"]), Lister("slow", ["c.example.com"], delay=0.6)
    resolve = Resolve()
    await run_agent(engine, scan, dom("example.com"), [fast, slow, resolve], None)
    assert slow.finished_at is not None
    # the barrier loop would start `a` only after `slow` had answered
    assert resolve.started["a.example.com"] < slow.finished_at - 0.3
    assert resolve.started["b.example.com"] < slow.finished_at - 0.3
    assert resolve.started["c.example.com"] >= slow.finished_at


async def test_the_streaming_scan_finds_exactly_what_the_round_loop_finds():
    tree = {"example.com": ["a.example.com", "b.example.com"], "a.example.com": ["a1.example.com"], "a1.example.com": ["a2.example.com"], "b.example.com": ["a1.example.com"]}
    results = {}
    for pipelined in (False, True):
        store, engine, scan = make()
        resolve = Resolve(tree)
        stats = await run_agent(engine, scan, dom("example.com"), [Lister("src", ["z.example.com"]), resolve], None, pipelined=pipelined)
        results[pipelined] = (
            sorted(e.entity.id for e in store.entities(scan)),
            sorted((e.src, e.rel, e.dst, e.evidence_ids) for e in store.edges(scan)),
            sorted(resolve.started),
            stats.modules_run,
            stats.rounds,
        )
    assert results[True] == results[False]


async def test_rounds_count_the_depth_of_the_discovery_not_the_number_of_batches():
    store, engine, scan = make()
    chain = {"example.com": ["a.example.com"], "a.example.com": ["b.example.com"], "b.example.com": ["c.example.com"]}
    stats = await run_agent(engine, scan, dom("example.com"), [Resolve(chain)], None)
    assert stats.rounds == 4 and stats.modules_run == 4 and stats.entities == 4


async def test_max_rounds_limits_the_depth():
    store, engine, scan = make()
    chain = {"example.com": ["a.example.com"], "a.example.com": ["b.example.com"], "b.example.com": ["c.example.com"]}
    resolve = Resolve(chain)
    stats = await run_agent(engine, scan, dom("example.com"), [resolve], None, max_rounds=2)
    assert sorted(resolve.started) == ["a.example.com", "example.com"] and stats.rounds == 2


async def test_the_step_budget_holds_and_the_cheap_lookups_come_first():
    store, engine, scan = make()
    resolve = Resolve({"example.com": [f"h{n}.example.com" for n in range(10)]})
    stats = await run_agent(engine, scan, dom("example.com"), [Lister("src", ["x.example.com"]), resolve], None, max_steps=4)
    assert stats.modules_run == 4 and stats.steps_exhausted is True
    assert "example.com" in resolve.started  # priority 0 (the lister) and 10 (the resolver) both ran on the apex


async def test_a_budget_that_is_exactly_enough_is_not_reported_as_exhausted():
    store, engine, scan = make()
    stats = await run_agent(engine, scan, dom("example.com"), [Resolve()], None, max_steps=1)
    assert stats.modules_run == 1 and stats.steps_exhausted is False


async def test_the_entity_cap_stops_new_lookups():
    store, engine, scan = make()
    resolve = Resolve({"example.com": [f"h{n}.example.com" for n in range(30)]})
    stats = await run_agent(engine, scan, dom("example.com"), [resolve], None, max_entities=10)
    assert stats.entities >= 10 and len(resolve.started) == 1  # the cap was reached by the first lookup's results


async def test_nothing_new_starts_after_the_deadline_and_running_lookups_are_cut():
    store = Store(":memory:")
    engine = Engine(store, ScopePolicy(domains=["example.com"]), ctx=None, deadline=Deadline(0.3))
    scan = store.create_scan("example.com")
    slow = Lister("slow", ["a.example.com"], delay=5.0)
    resolve = Resolve()
    started = time.monotonic()
    stats = await run_agent(engine, scan, dom("example.com"), [slow, resolve], None)
    assert time.monotonic() - started < 2.0 and stats.deadline_hit is True
    assert "a.example.com" not in resolve.started


async def test_cancelling_the_scan_cancels_the_lookups_in_flight():
    store, engine, scan = make()
    slow = Lister("slow", ["a.example.com"], delay=30.0)
    task = asyncio.ensure_future(run_agent(engine, scan, dom("example.com"), [slow, Resolve()], None))
    await asyncio.sleep(0.1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0.05)
    assert slow.finished_at is None
    assert not [t for t in asyncio.all_tasks() if t is not asyncio.current_task() and not t.done()]


async def test_a_planner_keeps_the_round_structure():
    """With a planner model the agent still ranks lookups round by round; the barrier is what lets it."""
    store, engine, scan = make()
    provider = ScriptedProvider(responder=lambda system, user, schema: {"choices": [0], "hypothesis": "h"} if schema["title"] == "Ranking" else {"settled": []})
    resolve = Resolve({"example.com": ["a.example.com", "b.example.com", "c.example.com"]})
    stats = await run_agent(engine, scan, dom("example.com"), [resolve], AIRuntime({"planner": provider}), max_steps=3)
    assert stats.ai_choices == 2 and stats.rounds == 3 and stats.steps_exhausted is True  # the planner chose in rounds 2 and 3


async def test_an_ai_without_a_planner_role_still_streams():
    store, engine, scan = make()
    resolve = Resolve({"example.com": ["a.example.com"]})
    stats = await run_agent(engine, scan, dom("example.com"), [resolve], AIRuntime({"writer": ScriptedProvider([])}))
    assert sorted(resolve.started) == ["a.example.com", "example.com"] and stats.ai_choices == 0
