import httpx

from scrutator.retry import RetryingTransport


async def run(items, **kw):
    sleeps, calls = [], []
    iterator = iter(items)

    async def fake_sleep(delay):
        sleeps.append(delay)

    def handler(request):
        calls.append(request)
        item = next(iterator)
        if isinstance(item, Exception):
            raise item
        status, headers = item if isinstance(item, tuple) else (item, {})
        return httpx.Response(status, headers=headers, text="body")

    transport = RetryingTransport(
        httpx.MockTransport(handler), sleep=fake_sleep, jitter=lambda: 1.0, **kw
    )
    async with httpx.AsyncClient(transport=transport) as client:
        try:
            result = await client.get("https://example.test/")
        except httpx.HTTPError as exc:
            result = exc
    return result, calls, sleeps


async def test_retries_server_errors_with_exponential_backoff():
    response, calls, sleeps = await run([503, 503, 200])
    assert response.status_code == 200
    assert len(calls) == 3
    assert sleeps == [1.0, 2.0]


async def test_returns_last_response_when_still_failing():
    response, calls, _ = await run([503, 503, 503])
    assert response.status_code == 503
    assert len(calls) == 3


async def test_retries_timeouts():
    response, calls, _ = await run([httpx.ReadTimeout("slow"), 200])
    assert response.status_code == 200
    assert len(calls) == 2


async def test_raises_when_timeouts_exhaust_attempts():
    result, calls, _ = await run([httpx.ReadTimeout("slow")] * 3)
    assert isinstance(result, httpx.ReadTimeout)
    assert len(calls) == 3


async def test_client_errors_are_not_retried():
    response, calls, _ = await run([404, 200])
    assert response.status_code == 404
    assert len(calls) == 1


async def test_retry_after_header_is_honoured_and_capped():
    _, _, sleeps = await run([(429, {"retry-after": "2"}), 200])
    assert sleeps == [2.0]
    _, _, capped = await run([(429, {"retry-after": "999"}), 200], max_delay=20.0)
    assert capped == [20.0]


async def test_a_request_can_ask_for_fewer_attempts():
    sleeps, calls = [], []

    async def fake_sleep(delay):
        sleeps.append(delay)

    def handler(request):
        calls.append(request)
        raise httpx.ConnectTimeout("no route")

    transport = RetryingTransport(httpx.MockTransport(handler), sleep=fake_sleep, jitter=lambda: 1.0)
    async with httpx.AsyncClient(transport=transport) as client:
        try:
            await client.get("https://example.test/", extensions={"scrutator_attempts": 2})
        except httpx.ConnectTimeout:
            pass
    assert len(calls) == 2 and len(sleeps) == 1


async def test_a_server_asking_for_a_long_wait_is_not_waited_for_when_told_to_give_up():
    response, calls, sleeps = await run([(429, {"retry-after": "60"}), 200], give_up_after=8.0)
    assert response.status_code == 429 and len(calls) == 1 and sleeps == []
    response, calls, sleeps = await run([(503, {"retry-after": "5"}), 200], give_up_after=8.0)
    assert response.status_code == 200 and sleeps == [5.0]  # a short wait is still honoured
    response, calls, sleeps = await run([429, 200], give_up_after=8.0)
    assert response.status_code == 200 and sleeps == [1.0]  # no Retry-After: the usual back-off


async def test_the_scan_context_gives_up_on_long_waits():
    from scrutator.context import GIVE_UP_AFTER_S, open_context

    async with open_context() as ctx:
        assert ctx.http._transport.give_up_after == GIVE_UP_AFTER_S == 8.0
