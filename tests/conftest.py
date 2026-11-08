import os

# Help output must be plain text whatever the environment: GitHub Actions makes Typer/Rich print colour codes that split
# option names (`--bundle`), and a narrow terminal wraps them. Set before anything imports typer.
os.environ["NO_COLOR"] = "1"
os.environ["_TYPER_FORCE_DISABLE_TERMINAL"] = "1"
os.environ["COLUMNS"] = "200"
os.environ.pop("FORCE_COLOR", None)

import httpx
import pytest

from scrutator.modules.base import ModuleContext


@pytest.fixture(autouse=True)
def no_rdap_pacing(monkeypatch):
    """rdap.org is paced to a request a second; the tests' mocked services need no manners."""
    from scrutator.modules import rdap

    monkeypatch.setattr(rdap, "PACE", (100_000, 100_000.0))
    from scrutator.modules import brand

    monkeypatch.setattr(brand, "PACE", 100_000.0)
    from scrutator.modules import crtsh

    monkeypatch.setattr(crtsh, "DB_FALLBACK", False)  # never a connection to crt.sh's database from a test


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
