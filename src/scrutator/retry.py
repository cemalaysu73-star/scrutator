import asyncio
import random
from collections.abc import Awaitable, Callable

import httpx

RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
_RETRY_EXCEPTIONS = (
    httpx.TimeoutException,
    httpx.ConnectError,
    httpx.ReadError,
    httpx.RemoteProtocolError,
)


class RetryingTransport(httpx.AsyncBaseTransport):
    """Retries transient failures (timeouts, connection errors, 429 and 5xx) with
    exponential backoff and jitter, honouring a capped Retry-After. If the last attempt
    still fails with a status code, that response is returned; a final exception is raised."""

    def __init__(
        self,
        inner: httpx.AsyncBaseTransport,
        *,
        attempts: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 20.0,
        give_up_after: float | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        jitter: Callable[[], float] = random.random,
    ) -> None:
        self._inner = inner
        self.attempts = attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        # A server that asks us to wait longer than this (Retry-After) is not waited for: its 429 or 5xx is
        # handed back at once and the caller reports the source as unavailable. A free tier's quota does not
        # come back within a scan, and a scan that sleeps 20 s twice for it ends 40 s later with nothing.
        self.give_up_after = give_up_after
        self._sleep = sleep
        self._jitter = jitter

    def _delay(self, attempt: int, retry_after: str | None) -> float:
        if retry_after and retry_after.isdigit():
            return min(float(retry_after), self.max_delay)
        backoff = min(self.max_delay, self.base_delay * 2 ** (attempt - 1))
        return backoff * (0.5 + self._jitter() / 2)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        # a module that knows its source is flaky can ask for fewer tries
        wanted = request.extensions.get("scrutator_attempts")
        attempts = min(self.attempts, wanted) if isinstance(wanted, int) and wanted >= 1 else self.attempts
        for attempt in range(1, attempts + 1):
            last = attempt == attempts
            try:
                response = await self._inner.handle_async_request(request)
            except _RETRY_EXCEPTIONS:
                if last:
                    raise
                await self._sleep(self._delay(attempt, None))
                continue
            if response.status_code in RETRY_STATUS and not last:
                asked = response.headers.get("retry-after")
                if self.give_up_after is not None and asked and asked.isdigit() and float(asked) > self.give_up_after:
                    return response
                delay = self._delay(attempt, response.headers.get("retry-after"))
                await response.aclose()
                await self._sleep(delay)
                continue
            return response
        raise RuntimeError("unreachable")

    async def aclose(self) -> None:
        await self._inner.aclose()
