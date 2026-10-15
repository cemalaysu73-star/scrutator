import asyncio

import httpx

from scrutator.ai.types import Runtime

_PROBES = (
    ("ollama", "http://127.0.0.1:11434", "/api/tags"),
    ("openai", "http://127.0.0.1:1234/v1", "/models"),
    ("openai", "http://127.0.0.1:8080/v1", "/models"),
)


async def _probe(client: httpx.AsyncClient, kind: str, base_url: str, path: str, timeout: float) -> Runtime | None:
    try:
        response = await client.get(base_url + path, timeout=timeout)
        data = response.json()
        if response.status_code != 200:
            return None
        if kind == "ollama":
            models = tuple(str(m["name"]) for m in data["models"])
        else:
            models = tuple(str(m["id"]) for m in data["data"])
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        return None
    return Runtime(kind, base_url, models)


async def detect_local(client: httpx.AsyncClient, timeout: float = 1.0) -> list[Runtime]:
    """Look for model servers on loopback: Ollama, LM Studio, llama.cpp server."""
    results = await asyncio.gather(*(_probe(client, k, b, p, timeout) for k, b, p in _PROBES))
    return [r for r in results if r is not None]
