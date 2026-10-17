from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx

from scrutator import __version__
from scrutator.modules.base import ModuleContext
from scrutator.resolver import DnsResolver
from scrutator.retry import RetryingTransport

GIVE_UP_AFTER_S = 12.0  # a source asking for a longer wait than this is not waited for (see RetryingTransport)


@asynccontextmanager
async def open_context() -> AsyncIterator[ModuleContext]:
    """HTTP client for the data-source modules: follows redirects, retries transient failures."""
    headers = {"User-Agent": f"scrutator/{__version__}"}
    transport = RetryingTransport(httpx.AsyncHTTPTransport(), give_up_after=GIVE_UP_AFTER_S)
    async with httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(60.0, connect=15.0),
        follow_redirects=True,
        headers=headers,
    ) as client:
        yield ModuleContext(http=client, resolver=DnsResolver(cache=True))


@asynccontextmanager
async def ai_client() -> AsyncIterator[httpx.AsyncClient]:
    """HTTP client for model endpoints: long read timeout (local models are slow),
    no redirects (an endpoint must not bounce a prompt elsewhere), no retries."""
    async with httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=5.0), follow_redirects=False) as client:
        yield client
