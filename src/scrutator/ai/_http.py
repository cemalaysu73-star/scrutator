import hashlib
import json
from typing import Any
from urllib.parse import urlsplit

import httpx

from scrutator.ai.types import AIError


async def post_json(
    client: httpx.AsyncClient, url: str, body: dict[str, Any], headers: dict[str, str] | None = None
) -> tuple[Any, int, str]:
    """POST a JSON body. Returns (response json, bytes sent, sha256 of the bytes sent).
    Error messages never include request headers, so API keys cannot leak into them."""
    payload = json.dumps(body).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    host = urlsplit(url).netloc
    try:
        response = await client.post(
            url, content=payload, headers={"content-type": "application/json", **(headers or {})}
        )
    except httpx.HTTPError as exc:
        raise AIError(f"request to {host} failed: {type(exc).__name__}") from exc
    if response.status_code >= 400:
        raise AIError(f"{host} returned HTTP {response.status_code}: {response.text[:200]}")
    try:
        return response.json(), len(payload), digest
    except ValueError as exc:
        raise AIError(f"{host} returned invalid JSON") from exc
