import asyncio

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
            Observation(
                Entity(type=t, value=v), rel, Evidence.create(self.name, f"fake {entity.value}", f"{rel}:{v}")
            )
            for t, v, rel in self.outputs
        ]


@pytest.fixture
def setup():
    store = Store(":memory:")
    scope = ScopePolicy(domains=["example.com"])
    engine = Engine(store, scope, ctx=None)
    scan = store.create_scan("example.com")
    store.upsert_entity(scan, dom("example.com"), ScopeState.IN)
    return store, engine, scan


async def test_in_scope_run_stores_edges_and_classifies_results(setup):
    store, engine, scan = setup
    module = Fake([(D, "www.example.com", "has_subdomain"), (D, "cdn.other.net", "cname_to"), (I, "192.0.2.9", "resolves_to")])
    new = await engine.run_module(scan, module, dom("example.com"))

    assert {e.value for e in new} == {"www.example.com", "192.0.2.9"}
    states = {s.entity.id: s.state for s in store.entities(scan)}
    assert states["domain:www.example.com"] is ScopeState.IN
    assert states["domain:cdn.other.net"] is ScopeState.OUT
    assert states["ip:192.0.2.9"] is ScopeState.LINKED
    assert len(store.edges(scan)) == 3
    assert store.verify_audit(scan)


async def test_out_of_scope_entity_is_not_run_and_is_audited(setup):
    store, engine, scan = setup
    store.upsert_entity(scan, dom("other.net"), ScopeState.OUT)
    module = Fake([(D, "x.other.net", "has_subdomain")])
    assert await engine.run_module(scan, module, dom("other.net")) == []
    assert module.calls == []
    assert store.audit_log(scan)[-1]["event"] == "denied"


async def test_unknown_entity_is_denied(setup):
    store, engine, scan = setup
    module = Fake()
    assert await engine.run_module(scan, module, dom("never-seen.example.com")) == []
    assert module.calls == []


async def test_active_modules_need_flag_and_in_scope_state(setup):
    store, engine, scan = setup
    active = Fake(mode=Mode.ACTIVE)
    assert await engine.run_module(scan, active, dom("example.com")) == []
    assert active.calls == []
    assert store.audit_log(scan)[-1]["event"] == "skipped"

    engine.allow_active = True
    await engine.run_module(scan, active, dom("example.com"))
    assert active.calls == ["domain:example.com"]

    ip = Entity(type=I, value="192.0.2.9")
    store.upsert_entity(scan, ip, ScopeState.LINKED)
    await engine.run_module(scan, active, ip)
    assert active.calls == ["domain:example.com"]
    assert store.audit_log(scan)[-1]["event"] == "denied"


async def test_module_exception_is_recorded_not_raised(setup):
    store, engine, scan = setup

    class Boom(Fake):
        async def run(self, entity, ctx):
            raise RuntimeError("source down")

    assert await engine.run_module(scan, Boom(), dom("example.com")) == []
    last = store.audit_log(scan)[-1]
    assert last["event"] == "error"
    assert "source down" in last["error"]


async def test_module_timeout_is_recorded(setup):
    store, engine, scan = setup

    class Slow(Fake):
        timeout = 0.05

        async def run(self, entity, ctx):
            await asyncio.sleep(1)
            return []

    assert await engine.run_module(scan, Slow(), dom("example.com")) == []
    assert store.audit_log(scan)[-1]["event"] == "error"


async def test_self_observations_are_ignored(setup):
    store, engine, scan = setup
    module = Fake([(D, "example.com", "related_host")])
    assert await engine.run_module(scan, module, dom("example.com")) == []
    assert store.edges(scan) == []
