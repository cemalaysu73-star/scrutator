from collections.abc import Iterable
from dataclasses import replace
from urllib.parse import urlsplit

import httpx

from scrutator.ai.config import AIConfig, AIMode
from scrutator.ai.detect import detect_local
from scrutator.ai.factory import DEFAULT_URLS, build_provider, resolve_roles
from scrutator.ai.net import is_loopback
from scrutator.ai.redact import Redactor
from scrutator.ai.runtime import AIRuntime


def cloud_hosts(config: AIConfig, cli_mode: AIMode | None) -> set[str]:
    """Remote endpoints this configuration could send data to, for the consent prompt."""
    mode = cli_mode or config.mode
    if mode in (AIMode.OFF, AIMode.LOCAL):
        return set()
    hosts = set()
    for spec in config.roles.values():
        url = spec.base_url or DEFAULT_URLS[spec.provider]
        if not is_loopback(url):
            hosts.add(urlsplit(url).netloc)
    return hosts


async def build_runtime(
    config: AIConfig,
    *,
    cli_mode: AIMode | None,
    model: str | None,
    consent_cloud: bool,
    redact: bool | None,
    client: httpx.AsyncClient,
    apex_domains: Iterable[str],
) -> tuple[AIRuntime | None, AIMode]:
    """Resolve the mode, probe for local servers only when that can matter, and build the
    providers. Returns (None, OFF) when no AI is in play."""
    effective = replace(config, mode=cli_mode or config.mode)
    runtimes = await detect_local(client) if effective.mode in (AIMode.AUTO, AIMode.LOCAL) else []
    mode, roles = resolve_roles(effective, runtimes, model_override=model)
    if mode is AIMode.OFF:
        return None, AIMode.OFF
    providers = {
        role: build_provider(spec, client, mode=mode, consent_cloud=consent_cloud)
        for role, spec in roles.items()
    }
    use_redaction = config.redact if redact is None else redact
    redactor = Redactor(apex_domains) if use_redaction else None
    return AIRuntime(providers, redactor=redactor), mode
