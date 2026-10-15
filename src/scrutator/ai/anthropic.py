import json
from typing import Any
from urllib.parse import urlsplit

import httpx

from scrutator.ai._http import post_json
from scrutator.ai.net import is_loopback
from scrutator.ai.types import AIError, Completion


class AnthropicProvider:
    """Claude through the Messages API. Structured output is a forced tool call, so the
    schema is enforced by the API and no native tool-calling skill is assumed elsewhere."""

    name = "anthropic"

    def __init__(
        self,
        client: httpx.AsyncClient,
        model: str,
        api_key: str,
        base_url: str = "https://api.anthropic.com",
    ) -> None:
        self.client = client
        self.model = model
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self.is_local = is_loopback(self.base_url)
        self.host = urlsplit(self.base_url).netloc

    async def complete_json(self, system: str, user: str, schema: dict[str, Any]) -> Completion:
        body = {
            "model": self.model,
            "max_tokens": 2048,
            "system": system,
            "messages": [{"role": "user", "content": user}],
            "tools": [
                {
                    "name": "respond",
                    "description": "Return the answer as structured data.",
                    "input_schema": schema,
                }
            ],
            "tool_choice": {"type": "tool", "name": "respond"},
        }
        headers = {"x-api-key": self._api_key, "anthropic-version": "2023-06-01"}
        data, size, digest = await post_json(self.client, f"{self.base_url}/v1/messages", body, headers)
        blocks = data.get("content") if isinstance(data, dict) else None
        tool = next(
            (b for b in blocks or [] if isinstance(b, dict) and b.get("type") == "tool_use"), None
        )
        if tool is None:
            raise AIError("anthropic returned no structured output")
        payload = tool.get("input")
        usage = data.get("usage") or {}
        return Completion(
            data=payload,
            text=json.dumps(payload),
            prompt_tokens=int(usage.get("input_tokens") or 0),
            completion_tokens=int(usage.get("output_tokens") or 0),
            bytes_sent=size,
            payload_sha256=digest,
        )
