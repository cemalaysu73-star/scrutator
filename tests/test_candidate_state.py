import pytest

from scrutator.engine import Engine
from scrutator.model import Entity, EntityType, Evidence, ScopeState
from scrutator.modules.base import Mode, Module, Observation
from scrutator.scope import ScopePolicy
from scrutator.store import Store

D, I = EntityType.DOMAIN, EntityType.IP


def dom(value):
    return Entity(type=D, value=value)


class Fake(Module):
    name = "fake"
    accepts = frozenset({D, I})

    def __init__(self, outputs=(), mode=Mode.PASSIVE):
        self.outputs = list(outputs)
        self.mode = mode
        self.calls = []

    async def run(self, entity, ctx):
        self.calls.append(entity.id)
        return [
            Observation(Entity(type=t, value=v), rel, Evidence.create(self.name, f"fake {entity.value}", f"{rel}:{v}"))
            for t, v, rel in self.outputs
        ]


@pytest.fixture
def setup():
    store = Store(":memory:")
    engine = Engine(store, ScopePolicy(domains=["example.com"]), ctx=None, allow_active=True)
    scan = store.create_scan("example.com")
    store.upsert_entity(scan, dom("example.com"), ScopeState.IN)
    store.upsert_entity(scan, dom("partner.test"), ScopeState.CANDIDATE)
    return store, engine, scan


def test_candidate_is_a_fourth_state_between_linked_and_in():
    assert ScopeState("candidate") is ScopeState.CANDIDATE
    assert [s.value for s in sorted(ScopeState, key=lambda s: s.rank)] == ["out", "linked", "candidate", "in"]


def test_a_candidate_is_promoted_to_in_but_never_demoted(setup):
    store, _, scan = setup
    assert store.upsert_entity(scan, dom("partner.test"), ScopeState.OUT) is False
    assert store.scope_state(scan, "domain:partner.test") is ScopeState.CANDIDATE
    assert store.upsert_entity(scan, dom("partner.test"), ScopeState.IN) is True
    assert store.scope_state(scan, "domain:partner.test") is ScopeState.IN


async def test_a_candidate_gets_passive_lookups_only(setup):
    store, engine, scan = setup
    passive = Fake([(D, "ns1.other.net", "ns"), (I, "192.0.2.7", "resolves_to"), (D, "www.example.com", "related_host")])
    await engine.run_module(scan, passive, dom("partner.test"))
    assert passive.calls == ["domain:partner.test"]
    states = {s.entity.id: s.state for s in store.entities(scan)}
    assert states["domain:ns1.other.net"] is ScopeState.OUT  # recorded, never queried
    assert states["ip:192.0.2.7"] is ScopeState.LINKED  # so that network lookups can follow
    assert states["domain:www.example.com"] is ScopeState.IN  # the user's own scope decides, not the candidate

    active = Fake(mode=Mode.ACTIVE)
    assert await engine.run_module(scan, active, dom("partner.test")) == []
    assert active.calls == []
    last = store.audit_log(scan)[-1]
    assert last["event"] == "denied" and "in-scope" in last["reason"]


async def test_an_out_of_scope_entity_still_gets_nothing(setup):
    store, engine, scan = setup
    store.upsert_entity(scan, dom("decoy.test"), ScopeState.OUT)
    module = Fake([(D, "x.decoy.test", "has_subdomain")])
    assert await engine.run_module(scan, module, dom("decoy.test")) == []
    assert module.calls == []


async def test_nothing_a_candidate_discovers_is_itself_a_candidate(setup):
    store, engine, scan = setup
    await engine.run_module(scan, Fake([(D, "deeper.partner.test", "has_subdomain")]), dom("partner.test"))
    assert store.scope_state(scan, "domain:deeper.partner.test") is ScopeState.OUT
