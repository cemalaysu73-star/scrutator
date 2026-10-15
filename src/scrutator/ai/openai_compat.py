from typing import Any
from urllib.parse import urlsplit

import httpx

from scrutator.ai._http import post_json
from scrutator.ai._json import parse_json_text
from scrutator.ai.net import is_loopback
from scrutator.ai.types import AIError, Completion


class OpenAICompatProvider:
    """Any OpenAI-compatible chat endpoint: llama.cpp server, LM Studio and vLLM locally,
    OpenAI, OpenRouter and similar in the cloud."""

    name = "openai"

    def __init__(
        self,
        client: httpx.AsyncClient,
        model: str,
        base_url: str = "https://api.openai.com/v1",
        api_key: str | None = None,
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
            "temperature": 0,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "response", "schema": schema, "strict": False},
            },
        }
        headers = {"authorization": f"Bearer {self._api_key}"} if self._api_key else {}
        data, size, digest = await post_json(self.client, f"{self.base_url}/chat/completions", body, headers)
        try:
            text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise AIError("unexpected reply from the chat endpoint") from exc
        usage = data.get("usage") or {}
        return Completion(
            data=parse_json_text(text or ""),
            text=text or "",
            prompt_tokens=int(usage.get("prompt_tokens") or 0),
            completion_tokens=int(usage.get("completion_tokens") or 0),
            bytes_sent=size,
            payload_sha256=digest,
        )
