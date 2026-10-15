import json

import httpx
import pytest
import respx

from scrutator.ai.anthropic import AnthropicProvider
from scrutator.ai.ollama import OllamaProvider
from scrutator.ai.openai_compat import OpenAICompatProvider
from scrutator.ai.types import AIError

SCHEMA = {"type": "object", "properties": {"answer": {"type": "integer"}}, "required": ["answer"]}


def body_of(route):
    return json.loads(route.calls.last.request.content)


async def test_ollama_sends_schema_as_format_and_parses_reply(http):
    provider = OllamaProvider(http, "qwen3:8b")
    reply = {
        "message": {"role": "assistant", "content": '{"answer": 7}'},
        "prompt_eval_count": 12,
        "eval_count": 5,
    }
    with respx.mock() as router:
        route = router.post("http://127.0.0.1:11434/api/chat").mock(return_value=httpx.Response(200, json=reply))
        completion = await provider.complete_json("be brief", "3+4?", SCHEMA)
    body = body_of(route)
    assert body["model"] == "qwen3:8b"
    assert body["format"] == SCHEMA
    assert body["stream"] is False
    assert [m["role"] for m in body["messages"]] == ["system", "user"]
    assert completion.data == {"answer": 7}
    assert (completion.prompt_tokens, completion.completion_tokens) == (12, 5)
    assert completion.bytes_sent > 0 and len(completion.payload_sha256) == 64
    assert provider.is_local is True and provider.host == "127.0.0.1:11434"


async def test_ollama_tolerates_fenced_and_unparseable_replies(http):
    provider = OllamaProvider(http, "m")
    with respx.mock() as router:
        router.post("http://127.0.0.1:11434/api/chat").mock(
            return_value=httpx.Response(200, json={"message": {"content": '```json\n{"answer": 1}\n```'}})
        )
        assert (await provider.complete_json("s", "u", SCHEMA)).data == {"answer": 1}
    with respx.mock() as router:
        router.post("http://127.0.0.1:11434/api/chat").mock(
            return_value=httpx.Response(200, json={"message": {"content": "cannot"}})
        )
        assert (await provider.complete_json("s", "u", SCHEMA)).data is None


async def test_ollama_http_and_network_errors_become_ai_errors(http):
    provider = OllamaProvider(http, "m")
    with respx.mock() as router:
        router.post("http://127.0.0.1:11434/api/chat").mock(return_value=httpx.Response(500, text="boom"))
        with pytest.raises(AIError):
            await provider.complete_json("s", "u", SCHEMA)
    with respx.mock() as router:
        router.post("http://127.0.0.1:11434/api/chat").mock(side_effect=httpx.ConnectError("down"))
        with pytest.raises(AIError):
            await provider.complete_json("s", "u", SCHEMA)


async def test_openai_compatible_local_server_without_key(http):
    provider = OpenAICompatProvider(http, "local-model", base_url="http://127.0.0.1:1234/v1")
    reply = {"choices": [{"message": {"content": '{"answer": 3}'}}], "usage": {"prompt_tokens": 9, "completion_tokens": 4}}
    with respx.mock() as router:
        route = router.post("http://127.0.0.1:1234/v1/chat/completions").mock(return_value=httpx.Response(200, json=reply))
        completion = await provider.complete_json("s", "u", SCHEMA)
    assert "authorization" not in route.calls.last.request.headers
    body = body_of(route)
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["schema"] == SCHEMA
    assert completion.data == {"answer": 3} and completion.prompt_tokens == 9
    assert provider.is_local is True


async def test_openai_compatible_cloud_sends_bearer_key(http):
    provider = OpenAICompatProvider(http, "gpt-x", api_key="sk-test")
    reply = {"choices": [{"message": {"content": '{"answer": 1}'}}]}
    with respx.mock() as router:
        route = router.post("https://api.openai.com/v1/chat/completions").mock(return_value=httpx.Response(200, json=reply))
        await provider.complete_json("s", "u", SCHEMA)
    assert route.calls.last.request.headers["authorization"] == "Bearer sk-test"
    assert provider.is_local is False and provider.host == "api.openai.com"


async def test_anthropic_forces_a_tool_call_and_reads_its_input(http):
    provider = AnthropicProvider(http, "claude-model", api_key="sk-ant-secret")
    reply = {
        "content": [{"type": "tool_use", "name": "respond", "input": {"answer": 9}}],
        "usage": {"input_tokens": 20, "output_tokens": 6},
    }
    with respx.mock() as router:
        route = router.post("https://api.anthropic.com/v1/messages").mock(return_value=httpx.Response(200, json=reply))
        completion = await provider.complete_json("sys", "usr", SCHEMA)
    request = route.calls.last.request
    assert request.headers["x-api-key"] == "sk-ant-secret"
    assert request.headers["anthropic-version"] == "2023-06-01"
    body = body_of(route)
    assert body["system"] == "sys"
    assert body["tool_choice"] == {"type": "tool", "name": "respond"}
    assert body["tools"][0]["input_schema"] == SCHEMA
    assert completion.data == {"answer": 9}
    assert (completion.prompt_tokens, completion.completion_tokens) == (20, 6)
    assert provider.is_local is False


async def test_anthropic_errors_never_leak_the_key(http):
    provider = AnthropicProvider(http, "m", api_key="sk-ant-secret")
    with respx.mock() as router:
        router.post("https://api.anthropic.com/v1/messages").mock(return_value=httpx.Response(401, json={"error": "bad key"}))
        with pytest.raises(AIError) as err:
            await provider.complete_json("s", "u", SCHEMA)
    assert "sk-ant-secret" not in str(err.value)
    with respx.mock() as router:
        router.post("https://api.anthropic.com/v1/messages").mock(
            return_value=httpx.Response(200, json={"content": [{"type": "text", "text": "hi"}]})
        )
        with pytest.raises(AIError):
            await provider.complete_json("s", "u", SCHEMA)
