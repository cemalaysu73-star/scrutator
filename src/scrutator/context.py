from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx

from scrutator import __version__
from scrutator.modules.base import ModuleContext
from scrutator.resolver import DnsResolver


@asynccontextmanager
async def open_context() -> AsyncIterator[ModuleContext]:
    headers = {"User-Agent": f"scrutator/{__version__}"}
    async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=15.0), follow_redirects=True, headers=headers) as client:
        yield ModuleContext(http=client, resolver=DnsResolver())
