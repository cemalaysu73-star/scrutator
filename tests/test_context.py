from scrutator.context import ai_client, open_context
from scrutator.retry import RetryingTransport


async def test_module_client_retries_transient_failures():
    async with open_context() as ctx:
        assert isinstance(ctx.http._transport, RetryingTransport)
        assert ctx.http.follow_redirects is True


async def test_ai_client_does_not_follow_redirects_or_retry():
    async with ai_client() as client:
        assert not isinstance(client._transport, RetryingTransport)
        assert client.follow_redirects is False
