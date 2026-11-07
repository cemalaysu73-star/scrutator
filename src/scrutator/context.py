from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx

from scrutator import __version__, proxy
from scrutator.egress import EgressGuard
from scrutator.modules.base import ModuleContext
from scrutator.resolver import DnsResolver
from scrutator.retry import RetryingTransport

GIVE_UP_AFTER_S = 12.0  # a source asking for a longer wait than this is not waited for (see RetryingTransport)


@asynccontextmanager
async def open_context(*, egress: EgressGuard | None = None) -> AsyncIterator[ModuleContext]:
    """HTTP client for the data-source modules: follows redirects, retries transient failures, and connects only
    where the egress policy allows (scrutator.egress): the source hosts, and RDAP servers a redirect led to."""
    headers = {"User-Agent": f"scrutator/{__version__}"}
    try:
        inner = httpx.AsyncHTTPTransport(proxy=proxy.httpx_proxy())  # None: direct; see scrutator.proxy
    except ImportError as exc:  # a SOCKS proxy needs the optional socksio package
        raise proxy.ProxyError("a SOCKS proxy for the HTTP data sources needs the optional package socksio: pip install 'scrutator[socks]'") from exc
    transport = RetryingTransport(inner, give_up_after=GIVE_UP_AFTER_S)
    async with httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(60.0, connect=15.0),
        follow_redirects=True,
        headers=headers,
        event_hooks=(egress or EgressGuard()).hooks(),
    ) as client:
        yield ModuleContext(http=client, resolver=DnsResolver(cache=True))


@asynccontextmanager
async def ai_client() -> AsyncIterator[httpx.AsyncClient]:
    """HTTP client for model endpoints: long read timeout (local models are slow),
    no redirects (an endpoint must not bounce a prompt elsewhere), no retries."""
    async with httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=5.0), follow_redirects=False) as client:
        yield client
