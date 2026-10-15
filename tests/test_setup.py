import httpx
import respx

from scrutator.ai.config import AIConfig, AIMode, RoleSpec
from scrutator.ai.setup import build_runtime, cloud_hosts

CLOUD = RoleSpec(provider="anthropic", model="claude-x", api_key_env="K")


def test_cloud_hosts_lists_only_remote_endpoints_that_could_be_used():
    cfg = AIConfig(roles={"planner": CLOUD, "verifier": RoleSpec(provider="ollama", model="m")})
    assert cloud_hosts(cfg, None) == {"api.anthropic.com"}
    assert cloud_hosts(cfg, AIMode.LOCAL) == set()
    assert cloud_hosts(cfg, AIMode.OFF) == set()
    assert cloud_hosts(AIConfig(), None) == set()


async def test_auto_builds_a_local_runtime_from_a_detected_server(http):
    with respx.mock() as router:
        router.get("http://127.0.0.1:11434/api/tags").mock(return_value=httpx.Response(200, json={"models": [{"name": "qwen3:8b"}]}))
        router.get("http://127.0.0.1:1234/v1/models").mock(side_effect=httpx.ConnectError("x"))
        router.get("http://127.0.0.1:8080/v1/models").mock(side_effect=httpx.ConnectError("x"))
        runtime, mode = await build_runtime(AIConfig(), cli_mode=None, model=None, consent_cloud=False, redact=None, client=http, apex_domains=["example.com"])
    assert mode is AIMode.LOCAL
    assert set(runtime.providers) == {"planner", "verifier", "writer"}
    assert runtime.providers["planner"].model == "qwen3:8b"
    assert runtime.redactor is None


async def test_auto_with_nothing_available_is_off(http):
    with respx.mock() as router:
        for url in ("http://127.0.0.1:11434/api/tags", "http://127.0.0.1:1234/v1/models", "http://127.0.0.1:8080/v1/models"):
            router.get(url).mock(side_effect=httpx.ConnectError("x"))
        runtime, mode = await build_runtime(AIConfig(), cli_mode=None, model=None, consent_cloud=False, redact=None, client=http, apex_domains=[])
    assert runtime is None and mode is AIMode.OFF


async def test_off_never_probes_the_network(http):
    with respx.mock(assert_all_mocked=True) as router:
        runtime, mode = await build_runtime(AIConfig(), cli_mode=AIMode.OFF, model=None, consent_cloud=False, redact=None, client=http, apex_domains=[])
        assert not router.calls
    assert runtime is None and mode is AIMode.OFF


async def test_cloud_config_builds_with_redaction(http):
    cfg = AIConfig(mode=AIMode.CLOUD, roles={"planner": CLOUD}, redact=True)
    import os

    os.environ["K"] = "sk-test"
    try:
        runtime, mode = await build_runtime(cfg, cli_mode=None, model=None, consent_cloud=True, redact=None, client=http, apex_domains=["acme.com"])
    finally:
        del os.environ["K"]
    assert mode is AIMode.CLOUD and runtime.redactor is not None
    assert runtime.redactor.redact("www.acme.com") == "www.d1.example"
    assert runtime.providers["writer"].name == "anthropic"
