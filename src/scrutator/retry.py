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
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        jitter: Callable[[], float] = random.random,
    ) -> None:
        self._inner = inner
        self.attempts = attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self._sleep = sleep
        self._jitter = jitter

    def _delay(self, attempt: int, retry_after: str | None) -> float:
        if retry_after and retry_after.isdigit():
            return min(float(retry_after), self.max_delay)
        backoff = min(self.max_delay, self.base_delay * 2 ** (attempt - 1))
        return backoff * (0.5 + self._jitter() / 2)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        for attempt in range(1, self.attempts + 1):
            last = attempt == self.attempts
            try:
                response = await self._inner.handle_async_request(request)
            except _RETRY_EXCEPTIONS:
                if last:
                    raise
                await self._sleep(self._delay(attempt, None))
                continue
            if response.status_code in RETRY_STATUS and not last:
                delay = self._delay(attempt, response.headers.get("retry-after"))
                await response.aclose()
                await self._sleep(delay)
                continue
            return response
        raise RuntimeError("unreachable")

    async def aclose(self) -> None:
        await self._inner.aclose()
