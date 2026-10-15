import pytest

from scrutator.ai.config import AIConfig, AIMode, RoleSpec, load_config
from scrutator.ai.factory import build_provider, resolve_roles
from scrutator.ai.types import AIError, EgressError, Runtime

OLLAMA = Runtime("ollama", "http://127.0.0.1:11434", ("qwen3:8b", "llama3.2"))
CLOUD = RoleSpec(provider="anthropic", model="claude-x", api_key_env="K")
LOCAL = RoleSpec(provider="ollama", model="qwen3:8b")


def test_load_config_reads_modes_and_roles(tmp_path):
    f = tmp_path / "c.toml"
    f.write_text(
        '[ai]\nmode = "hybrid"\nredact = true\nmax_steps = 30\n'
        '[ai.planner]\nprovider = "anthropic"\nmodel = "claude-x"\napi_key_env = "K"\n'
        '[ai.verifier]\nprovider = "ollama"\nmodel = "qwen3:8b"\nbase_url = "http://localhost:11434"\n'
    )
    cfg = load_config(f)
    assert cfg.mode is AIMode.HYBRID and cfg.redact is True and cfg.max_steps == 30
    assert cfg.roles["planner"].provider == "anthropic"
    assert cfg.roles["verifier"].base_url == "http://localhost:11434"
    assert "writer" not in cfg.roles


def test_missing_default_config_is_fine_but_explicit_one_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr("scrutator.ai.config.default_config_path", lambda: tmp_path / "none.toml")
    assert load_config(None) == AIConfig()
    with pytest.raises(ValueError):
        load_config(tmp_path / "missing.toml")


@pytest.mark.parametrize(
    "text",
    [
        '[ai]\nmode = "turbo"\n',
        '[ai]\nbogus = 1\n',
        '[ai.planner]\nprovider = "ollama"\nmodel = "m"\nextra = 1\n',
        '[ai.planner]\nprovider = "martian"\nmodel = "m"\n',
        '[ai.planner]\nprovider = "ollama"\nmodel = ""\n',
    ],
)
def test_invalid_config_is_rejected(tmp_path, text):
    f = tmp_path / "c.toml"
    f.write_text(text)
    with pytest.raises(ValueError):
        load_config(f)


def test_auto_uses_a_detected_local_runtime_for_every_role():
    mode, roles = resolve_roles(AIConfig(), [OLLAMA])
    assert mode is AIMode.LOCAL
    assert {r: s.model for r, s in roles.items()} == {"planner": "qwen3:8b", "verifier": "qwen3:8b", "writer": "qwen3:8b"}
    assert roles["planner"].provider == "ollama"


def test_auto_without_runtime_or_roles_is_off():
    assert resolve_roles(AIConfig(), []) == (AIMode.OFF, {})
    assert resolve_roles(AIConfig(), [Runtime("ollama", "http://127.0.0.1:11434", ())]) == (AIMode.OFF, {})


def test_model_override_applies_to_detected_and_configured_roles():
    _, roles = resolve_roles(AIConfig(), [OLLAMA], model_override="llama3.2")
    assert {s.model for s in roles.values()} == {"llama3.2"}
    cfg = AIConfig(roles={"planner": CLOUD})
    _, roles = resolve_roles(cfg, [], model_override="other")
    assert roles["planner"].model == "other"


def test_auto_with_configured_roles_infers_mode():
    assert resolve_roles(AIConfig(roles={"planner": LOCAL}), [])[0] is AIMode.LOCAL
    assert resolve_roles(AIConfig(roles={"planner": CLOUD}), [])[0] is AIMode.CLOUD
    mixed = AIConfig(roles={"planner": CLOUD, "verifier": LOCAL})
    mode, roles = resolve_roles(mixed, [])
    assert mode is AIMode.HYBRID
    assert set(roles) == {"planner", "verifier", "writer"}


def test_explicit_modes_validate_their_inputs():
    with pytest.raises(AIError):
        resolve_roles(AIConfig(mode=AIMode.LOCAL), [])
    with pytest.raises(AIError):
        resolve_roles(AIConfig(mode=AIMode.CLOUD), [OLLAMA])
    assert resolve_roles(AIConfig(mode=AIMode.OFF), [OLLAMA]) == (AIMode.OFF, {})
    assert resolve_roles(AIConfig(mode=AIMode.LOCAL), [OLLAMA])[0] is AIMode.LOCAL


def test_local_mode_refuses_a_remote_endpoint():
    with pytest.raises(EgressError):
        build_provider(CLOUD, None, mode=AIMode.LOCAL, consent_cloud=True, env={"K": "x"})


def test_cloud_endpoint_needs_consent_and_a_key():
    with pytest.raises(EgressError):
        build_provider(CLOUD, None, mode=AIMode.CLOUD, consent_cloud=False, env={"K": "x"})
    with pytest.raises(AIError):
        build_provider(CLOUD, None, mode=AIMode.CLOUD, consent_cloud=True, env={})
    with pytest.raises(AIError):
        build_provider(RoleSpec(provider="openai", model="m"), None, mode=AIMode.CLOUD, consent_cloud=True, env={})


def test_providers_are_built_for_each_kind():
    cloud = build_provider(CLOUD, None, mode=AIMode.CLOUD, consent_cloud=True, env={"K": "secret"})
    assert cloud.name == "anthropic" and cloud.is_local is False
    local = build_provider(LOCAL, None, mode=AIMode.LOCAL)
    assert local.name == "ollama" and local.is_local is True
    lm = build_provider(
        RoleSpec(provider="openai", model="m", base_url="http://127.0.0.1:1234/v1"), None, mode=AIMode.LOCAL
    )
    assert lm.name == "openai" and lm.is_local is True
    with pytest.raises(AIError):
        build_provider(RoleSpec(provider="ollama", model="m"), None, mode=AIMode.OFF)
