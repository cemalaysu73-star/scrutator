"""v0.7 task 2: a lookup's results are written in one transaction, not one commit per record. The store
is touched from the event loop thread, so every commit stalls all the other lookups."""

import pytest

from scrutator.model import Entity, EntityType, Evidence, ScopeState
from scrutator.store import Store


def dom(value):
    return Entity(type=EntityType.DOMAIN, value=value)


def commits(store):
    seen = []
    store._db.set_trace_callback(lambda statement: seen.append(statement) if statement.strip().upper() == "COMMIT" else None)
    return seen


def test_a_batch_commits_once_for_all_the_records_written_inside_it(tmp_path):
    store = Store(tmp_path / "s.db")
    sid = store.create_scan("example.com")
    seen = commits(store)
    with store.batch():
        for n in range(20):
            entity = dom(f"h{n}.example.com")
            evidence = Evidence.create("crtsh", f"GET https://crt.sh/?q={n}", "x")
            store.add_evidence(evidence)
            store.upsert_entity(sid, entity, ScopeState.IN)
            store.add_edge(sid, "domain:example.com", "has_subdomain", entity.id, [evidence.id])
            store.add_scan_evidence(sid, evidence.id)
        store.append_audit(sid, {"event": "ok"})
    assert len(seen) == 1
    assert len(store.entities(sid)) == 20 and len(store.edges(sid)) == 20 and store.verify_audit(sid)


def test_without_a_batch_every_write_still_commits_on_its_own(tmp_path):
    store = Store(tmp_path / "s.db")
    sid = store.create_scan("example.com")
    seen = commits(store)
    store.add_evidence(Evidence.create("crtsh", "GET x", "y"))
    store.upsert_entity(sid, dom("a.example.com"), ScopeState.IN)
    assert len(seen) == 2


def test_batches_nest_and_an_error_rolls_the_whole_batch_back(tmp_path):
    store = Store(tmp_path / "s.db")
    sid = store.create_scan("example.com")
    with pytest.raises(RuntimeError):
        with store.batch():
            store.upsert_entity(sid, dom("a.example.com"), ScopeState.IN)
            with store.batch():
                store.upsert_entity(sid, dom("b.example.com"), ScopeState.IN)
            raise RuntimeError("boom")
    assert store.entities(sid) == []
    with store.batch():
        with store.batch():
            store.upsert_entity(sid, dom("c.example.com"), ScopeState.IN)
        assert store.scope_state(sid, "domain:c.example.com") is ScopeState.IN  # readable inside the batch
    assert [e.entity.value for e in store.entities(sid)] == ["c.example.com"]


def test_the_audit_chain_is_the_same_with_and_without_batching(tmp_path):
    plain, batched = Store(":memory:"), Store(":memory:")
    for store in (plain, batched):
        store.create_scan("example.com")
    records = [{"event": "ok", "n": n} for n in range(5)]
    for record in records:
        plain.append_audit(1, record)
    with batched.batch():
        for record in records:
            batched.append_audit(1, record)
    assert plain.audit_rows(1) == batched.audit_rows(1) and batched.verify_audit(1)


async def test_the_engine_writes_a_lookups_results_in_one_transaction(tmp_path):
    from scrutator.engine import Engine
    from scrutator.modules.base import Module, Observation
    from scrutator.scope import ScopePolicy

    class Many(Module):
        name = "many"
        accepts = frozenset({EntityType.DOMAIN})

        async def run(self, entity, ctx):
            return [
                Observation(dom(f"h{n}.example.com"), "has_subdomain", Evidence.create("many", f"many {n}", f"p{n}"))
                for n in range(40)
            ]

    store = Store(tmp_path / "s.db")
    sid = store.create_scan("example.com")
    store.upsert_entity(sid, dom("example.com"), ScopeState.IN)
    engine = Engine(store, ScopePolicy(domains=["example.com"]), ctx=None)
    seen = commits(store)
    new = await engine.run_module(sid, Many(), dom("example.com"))
    assert len(new) == 40 and len(store.edges(sid)) == 40
    assert len(seen) == 1  # 40 evidence records, 40 entities, 40 edges and the audit record: one commit
    assert store.verify_audit(sid)
