import json

from scrutator.model import Entity, EntityType
from scrutator.modules.base import Module
from scrutator.scan import run_scan
from scrutator.scope import ScopePolicy
from scrutator.store import Store


class Nothing(Module):
    name = "nothing"
    accepts = frozenset({EntityType.DOMAIN})

    async def run(self, entity, ctx):
        return []


async def test_run_scan_records_the_scope_it_ran_under():
    store = Store(":memory:")
    scope = ScopePolicy(domains=["example.com"])
    scan_id, _ = await run_scan(Entity(type=EntityType.DOMAIN, value="example.com"), scope, store, None, modules=[Nothing()])
    assert json.loads(store.get_meta(scan_id, "scope")) == scope.to_dict()
