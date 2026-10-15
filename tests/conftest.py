import httpx
import pytest

from scrutator.modules.base import ModuleContext


class FakeResolver:
    def __init__(self, records=None):
        self.records = records or {}
        self.calls = []

    async def lookup(self, name, rtype):
        self.calls.append((name, rtype))
        return list(self.records.get((name, rtype), []))


@pytest.fixture
async def http():
    async with httpx.AsyncClient(follow_redirects=True) as client:
        yield client


@pytest.fixture
def make_ctx(http):
    def _make(records=None):
        return ModuleContext(http=http, resolver=FakeResolver(records))

    return _make
