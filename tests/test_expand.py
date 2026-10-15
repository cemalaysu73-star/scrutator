import pytest

from scrutator.engine import Engine
from scrutator.expand import expand
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
            Observation(dom(child), rel, Evidence.create("tree", f"tree {entity.value}", f"{rel}:{child}"))
            for child, rel in self.mapping.get(entity.value, [])
        ]


@pytest.fixture
def env():
    store = Store(":memory:")
    engine = Engine(store, ScopePolicy(domains=["example.com"]), ctx=None)
    return store, engine, store.create_scan("example.com")


async def test_expands_to_fixpoint_without_repeats_and_skips_out_of_scope(env):
    store, engine, scan = env
    tree = Tree(
        {
            "example.com": [("a.example.com", "has_subdomain"), ("x.other.net", "related_host")],
            "a.example.com": [("b.example.com", "has_subdomain"), ("example.com", "related_host")],
        }
    )
    stats = await expand(engine, scan, dom("example.com"), [tree])

    assert sorted(tree.calls) == ["a.example.com", "b.example.com", "example.com"]
    states = {s.entity.value: s.state for s in store.entities(scan)}
    assert states == {
        "example.com": ScopeState.IN,
        "a.example.com": ScopeState.IN,
        "b.example.com": ScopeState.IN,
        "x.other.net": ScopeState.OUT,
    }
    assert stats.rounds == 3
    assert stats.modules_run == 3
    assert stats.entities == 4


async def test_seed_out_of_scope_is_rejected(env):
    _, engine, scan = env
    with pytest.raises(ValueError):
        await expand(engine, scan, dom("other.net"), [Tree({})])


async def test_max_rounds_limits_depth(env):
    store, engine, scan = env
    tree = Tree({"example.com": [("a.example.com", "has_subdomain")], "a.example.com": [("b.example.com", "has_subdomain")]})
    stats = await expand(engine, scan, dom("example.com"), [tree], max_rounds=1)
    assert tree.calls == ["example.com"]
    assert stats.rounds == 1


async def test_max_entities_stops_expansion(env):
    store, engine, scan = env
    tree = Tree(
        {
            "example.com": [("a.example.com", "has_subdomain"), ("x.other.net", "related_host")],
            "a.example.com": [("b.example.com", "has_subdomain")],
        }
    )
    await expand(engine, scan, dom("example.com"), [tree], max_entities=2)
    assert "a.example.com" not in tree.calls
