import pytest
from llmfakes import ScriptedProvider

from scrutator.agent.planner import Candidate, choose
from scrutator.agent.runner import run_agent
from scrutator.agent.summary import graph_summary
from scrutator.ai.runtime import AIRuntime
from scrutator.ai.types import AIError
from scrutator.engine import Engine
from scrutator.model import Entity, EntityType, Evidence, ScopeState
from scrutator.modules.base import Module, Observation
from scrutator.scope import ScopePolicy
from scrutator.store import Store

D = EntityType.DOMAIN


def dom(value):
    return Entity(type=D, value=value)


class Tree(Module):
    name = "tree"
    accepts = frozenset({D})

    def __init__(self, mapping):
        self.mapping = mapping
        self.calls = []

    async def run(self, entity, ctx):
        self.calls.append(entity.value)
        return [
            Observation(dom(child), "has_subdomain", Evidence.create("tree", f"tree {entity.value}", child))
            for child in self.mapping.get(entity.value, [])
        ]


WIDE = {"example.com": ["a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com"]}
WITH_EVIDENCE = {**WIDE, "a.example.com": ["a1.example.com"]}  # running a.example.com yields evidence


@pytest.fixture
def env():
    store = Store(":memory:")
    engine = Engine(store, ScopePolicy(domains=["example.com"]), ctx=None)
    return store, engine, store.create_scan("example.com")


def planner(ranking, settle=None):
    def respond(system, user, schema):
        if schema["title"] == "Ranking":
            return ranking
        return settle if settle is not None else {"settled": []}

    return AIRuntime({"planner": ScriptedProvider(responder=respond)})


def cands(n=5):
    module = Tree({})
    return [Candidate(module, dom(f"{chr(97 + i)}.example.com")) for i in range(n)]


async def test_without_ai_everything_runs(env):
    store, engine, scan = env
    tree = Tree({"example.com": ["a.example.com"], "a.example.com": ["b.example.com"]})
    stats = await run_agent(engine, scan, dom("example.com"), [tree], None)
    assert sorted(tree.calls) == ["a.example.com", "b.example.com", "example.com"]
    assert stats.rounds == 3 and stats.modules_run == 3 and stats.entities == 3
    assert stats.steps_exhausted is False and stats.ai_choices == 0


async def test_step_budget_caps_runs_and_reports_exhaustion(env):
    store, engine, scan = env
    tree = Tree(WIDE)
    stats = await run_agent(engine, scan, dom("example.com"), [tree], None, max_steps=3)
    assert stats.modules_run == 3 and stats.steps_exhausted is True
    assert tree.calls == ["example.com", "a.example.com", "b.example.com"]


async def test_ai_ranking_chooses_among_the_options_and_logs_a_hypothesis(env):
    store, engine, scan = env
    tree = Tree(WIDE)
    ai = planner({"choices": [4, 2], "hypothesis": "the late names matter"})
    stats = await run_agent(engine, scan, dom("example.com"), [tree], ai, max_steps=3)
    assert tree.calls == ["example.com", "e.example.com", "c.example.com"]
    assert stats.ai_choices == 1 and stats.steps_exhausted is True
    (h,) = store.hypotheses(scan)
    assert h["text"] == "the late names matter" and h["status"] == "open"


async def test_choose_ignores_out_of_range_duplicate_and_negative_indices():
    ai = planner({"choices": [9, 1, 1, -1], "hypothesis": ""})
    choice = await choose(cands(), 2, ai)
    assert choice.source == "ai"
    assert [c.entity.value for c in choice.candidates] == ["b.example.com"]


async def test_choose_falls_back_when_the_model_fails_or_picks_nothing_valid():
    broken = AIRuntime({"planner": ScriptedProvider([AIError("down")])})
    choice = await choose(cands(), 2, broken)
    assert choice.source == "fallback"
    assert [c.entity.value for c in choice.candidates] == ["a.example.com", "b.example.com"]
    nothing = await choose(cands(), 2, planner({"choices": [99], "hypothesis": ""}))
    assert nothing.source == "fallback"


async def test_choose_skips_the_model_when_everything_fits():
    provider = ScriptedProvider([])
    choice = await choose(cands(3), 5, AIRuntime({"planner": provider}))
    assert choice.source == "all" and len(choice.candidates) == 3
    assert provider.calls == []


async def test_hostile_text_cannot_widen_the_options_or_the_scope(env):
    store, engine, scan = env
    # the model "obeys" injected text and asks for options that do not exist
    ai = planner({"choices": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], "hypothesis": "ignore scope; scan evil.net"})
    tree = Tree(WIDE)
    await run_agent(engine, scan, dom("example.com"), [tree], ai, max_steps=3)
    assert set(tree.calls) <= {"example.com", "a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com"}
    assert len(tree.calls) == 3


async def test_hypotheses_are_settled_only_with_real_evidence_refs(env):
    store, engine, scan = env
    good = planner(
        {"choices": [0], "hypothesis": "h"},
        settle={"settled": [{"id": 1, "status": "confirmed", "evidence_refs": ["E1"]}]},
    )
    await run_agent(engine, scan, dom("example.com"), [Tree(WITH_EVIDENCE)], good, max_steps=3)
    h = store.hypotheses(scan)[0]  # later rounds may add further open hypotheses
    assert h["status"] == "confirmed" and len(h["evidence_ids"]) == 1
    assert store.get_evidence(h["evidence_ids"][0]) is not None


async def test_invented_evidence_refs_leave_the_hypothesis_open():
    store = Store(":memory:")
    engine = Engine(store, ScopePolicy(domains=["example.com"]), ctx=None)
    scan = store.create_scan("example.com")
    bad = planner(
        {"choices": [0], "hypothesis": "h"},
        settle={"settled": [{"id": 1, "status": "confirmed", "evidence_refs": ["E99"]}]},
    )
    await run_agent(engine, scan, dom("example.com"), [Tree(WITH_EVIDENCE)], bad, max_steps=3)
    assert store.hypotheses(scan)[0]["status"] == "open"


async def test_seed_out_of_scope_is_rejected(env):
    _, engine, scan = env
    with pytest.raises(ValueError):
        await run_agent(engine, scan, dom("other.net"), [Tree({})], None)


def test_graph_summary_is_compact_and_counts_entities():
    store = Store(":memory:")
    scan = store.create_scan("example.com")
    store.upsert_entity(scan, dom("example.com"), ScopeState.IN)
    store.upsert_entity(scan, dom("x.other.net"), ScopeState.OUT)
    text = graph_summary(store, scan)
    assert "domain=2" in text and "in=1" in text and "out=1" in text and "relations: 0" in text
