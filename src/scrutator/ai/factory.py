import os
from collections.abc import Mapping
from dataclasses import replace

import httpx

from scrutator.ai.anthropic import AnthropicProvider
from scrutator.ai.config import ROLES, AIConfig, AIMode, RoleSpec
from scrutator.ai.net import is_loopback
from scrutator.ai.ollama import OllamaProvider
from scrutator.ai.openai_compat import OpenAICompatProvider
from scrutator.ai.types import AIError, EgressError, LLMProvider, Runtime

DEFAULT_URLS = {
    "ollama": "http://127.0.0.1:11434",
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com",
}


def _base_url(spec: RoleSpec) -> str:
    return spec.base_url or DEFAULT_URLS[spec.provider]


def _local_spec(runtime: Runtime, model_override: str | None) -> RoleSpec:
    return RoleSpec(
        provider="ollama" if runtime.kind == "ollama" else "openai",
        model=model_override or runtime.models[0],
        base_url=runtime.base_url,
    )


def _fill(roles: Mapping[str, RoleSpec]) -> dict[str, RoleSpec]:
    first = next(iter(roles.values()))
    return {role: roles.get(role, first) for role in ROLES}


def resolve_roles(
    config: AIConfig, runtimes: list[Runtime], *, model_override: str | None = None
) -> tuple[AIMode, dict[str, RoleSpec]]:
    """Decide the effective mode and the provider for each role. Never falls back to a
    cloud endpoint on its own: cloud roles exist only if the user configured them."""
    mode = config.mode
    if mode is AIMode.OFF:
        return AIMode.OFF, {}
    usable = [r for r in runtimes if r.models]
    configured = dict(config.roles)
    if model_override:
        configured = {role: replace(spec, model=model_override) for role, spec in configured.items()}

    if mode is AIMode.AUTO:
        if configured:
            roles = _fill(configured)
        elif usable:
            spec = _local_spec(usable[0], model_override)
            return AIMode.LOCAL, {role: spec for role in ROLES}
        else:
            return AIMode.OFF, {}
        local_flags = {is_loopback(_base_url(spec)) for spec in roles.values()}
        if local_flags == {True}:
            return AIMode.LOCAL, roles
        return (AIMode.CLOUD if local_flags == {False} else AIMode.HYBRID), roles

    if mode is AIMode.LOCAL:
        if configured:
            return AIMode.LOCAL, _fill(configured)
        if usable:
            spec = _local_spec(usable[0], model_override)
            return AIMode.LOCAL, {role: spec for role in ROLES}
        raise AIError("local AI requested, but no local runtime was found and no [ai.<role>] is configured")

    if not configured:
        raise AIError(f"{mode.value} mode needs at least one [ai.<role>] section in the config file")
    return mode, _fill(configured)


def build_provider(
    spec: RoleSpec,
    client: httpx.AsyncClient | None,
    *,
    mode: AIMode,
    consent_cloud: bool = False,
    env: Mapping[str, str] | None = None,
) -> LLMProvider:
    """Create the adapter for one role, enforcing the egress rules for the mode."""
    if mode is AIMode.OFF:
        raise AIError("AI is off")
    env = os.environ if env is None else env
    base_url = _base_url(spec)
    local = is_loopback(base_url)
    if not local:
        if mode is AIMode.LOCAL:
            raise EgressError(f"local mode: {base_url} is not a loopback address")
        if not consent_cloud:
            raise EgressError(f"{base_url} is a cloud endpoint and needs explicit consent")
    api_key = env.get(spec.api_key_env) if spec.api_key_env else None
    if not local and not api_key:
        raise AIError(
            f"{spec.provider} needs an API key: set api_key_env in the config and export that variable"
        )
    if spec.provider == "ollama":
        return OllamaProvider(client, spec.model, base_url)  # type: ignore[arg-type]
    if spec.provider == "openai":
        return OpenAICompatProvider(client, spec.model, base_url, api_key)  # type: ignore[arg-type]
    return AnthropicProvider(client, spec.model, api_key or "", base_url)  # type: ignore[arg-type]
