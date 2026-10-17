"""Pacing for services that answer a burst with 429.

rdap.org sits behind Cloudflare and refuses (HTTP 429, `Retry-After: 9` or `10`) after about ten requests
in a few seconds from one address; measured on 2026-10-17 with a burst of 40 and with one request every
0.5 s (the eleventh was refused). A scan that needs a lookup per network is better off spending a request
a second than being told to go away for ten seconds and retrying in a crowd.
"""

import asyncio
import time
from collections.abc import Awaitable, Callable


class Pacer:
    """A token bucket: `burst` requests may go at once, after that `per_second` of them every second."""

    def __init__(
        self,
        burst: int,
        per_second: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.burst, self.per_second = float(burst), float(per_second)
        self._clock, self._sleep = clock, sleep
        self._tokens = self.burst
        self._stamp = clock()

    def _refill(self) -> None:
        now = self._clock()
        self._tokens = min(self.burst, self._tokens + (now - self._stamp) * self.per_second)
        self._stamp = now

    async def take(self) -> None:
        """Wait until one request may go."""
        while True:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
            await self._sleep((1.0 - self._tokens) / self.per_second)
