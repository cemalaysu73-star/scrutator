import pytest
from llmfakes import ScriptedProvider
from pydantic import BaseModel

from scrutator.ai.redact import Redactor
from scrutator.ai.runtime import AIRuntime
from scrutator.ai.types import AIError
from scrutator.store import Store


class Echo(BaseModel):
    text: str


def echo_responder(system, user, schema):
    return {"text": user}


async def test_local_provider_gets_the_real_prompt_and_no_egress_record():
    store = Store(":memory:")
    sid = store.create_scan("acme.com")
    provider = ScriptedProvider(responder=echo_responder, is_local=True)
    runtime = AIRuntime({"planner": provider}, redactor=Redactor(["acme.com"]))
    runtime.bind(store, sid)
    result = await runtime.generate("planner", "sys", "www.acme.com is up", Echo)
    assert provider.calls[0]["user"] == "www.acme.com is up"
    assert result.text == "www.acme.com is up"
    assert store.egress_log(sid) == []
    assert runtime.prompt_tokens > 0 and runtime.completion_tokens > 0


async def test_cloud_provider_gets_pseudonyms_and_the_answer_is_restored():
    store = Store(":memory:")
    sid = store.create_scan("acme.com")
    provider = ScriptedProvider(responder=echo_responder, is_local=False, name="anthropic", model="claude-x")
    runtime = AIRuntime({"writer": provider}, redactor=Redactor(["acme.com"]))
    runtime.bind(store, sid)
    result = await runtime.generate("writer", "sys acme.com", "www.acme.com at 192.0.2.7", Echo)
    sent = provider.calls[0]
    assert "acme.com" not in sent["system"] + sent["user"]
    assert "192.0.2.7" not in sent["user"]
    assert result.text == "www.acme.com at 192.0.2.7"
    (row,) = store.egress_log(sid)
    assert (row["role"], row["provider"], row["model"], row["host"]) == ("writer", "anthropic", "claude-x", "api.fake.test")
    assert row["redacted"] is True and row["bytes_sent"] > 0


async def test_cloud_without_redactor_is_logged_as_not_redacted():
    store = Store(":memory:")
    sid = store.create_scan("x.com")
    provider = ScriptedProvider(responder=echo_responder, is_local=False)
    runtime = AIRuntime({"planner": provider})
    runtime.bind(store, sid)
    await runtime.generate("planner", "s", "u", Echo)
    assert store.egress_log(sid)[0]["redacted"] is False


async def test_every_repair_attempt_is_an_egress_record():
    store = Store(":memory:")
    sid = store.create_scan("x.com")
    provider = ScriptedProvider([{"wrong": 1}, {"text": "ok"}], is_local=False)
    runtime = AIRuntime({"planner": provider})
    runtime.bind(store, sid)
    await runtime.generate("planner", "s", "u", Echo)
    assert len(store.egress_log(sid)) == 2


async def test_missing_role_is_an_error():
    runtime = AIRuntime({"planner": ScriptedProvider([])})
    with pytest.raises(AIError):
        await runtime.generate("verifier", "s", "u", Echo)
    assert runtime.has("planner") and not runtime.has("planner", "verifier")


def test_describe_lists_providers_without_secrets():
    runtime = AIRuntime(
        {"planner": ScriptedProvider([], model="qwen3:8b"), "writer": ScriptedProvider([], is_local=False, name="anthropic", model="c")},
        redactor=Redactor(),
    )
    info = runtime.describe()
    assert info["providers"]["planner"] == {"provider": "fake", "model": "qwen3:8b", "local": True}
    assert info["providers"]["writer"]["local"] is False
    assert info["redacted"] is True
