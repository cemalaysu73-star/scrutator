from typing import Any
from urllib.parse import urlsplit

import httpx

from scrutator.ai._http import post_json
from scrutator.ai._json import parse_json_text
from scrutator.ai.net import is_loopback
from scrutator.ai.types import AIError, Completion


class OllamaProvider:
    """Ollama's native chat API. The JSON schema goes in `format`, which constrains
    generation token by token. Thinking is switched off: on a 9B reasoning model it turned a
    one-second answer into fifteen (measured), and the schema already forces the output shape."""

    name = "ollama"

    def __init__(self, client: httpx.AsyncClient, model: str, base_url: str = "http://127.0.0.1:11434") -> None:
        self.client = client
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.is_local = is_loopback(self.base_url)
        self.host = urlsplit(self.base_url).netloc

    async def complete_json(self, system: str, user: str, schema: dict[str, Any]) -> Completion:
        body = {
            "model": self.model,
            "stream": False,
            "format": schema,
            "think": False,
            "options": {"temperature": 0},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        url = f"{self.base_url}/api/chat"
        try:
            data, size, digest = await post_json(self.client, url, body)
        except AIError as exc:
            if "think" not in str(exc).lower():
                raise
            body.pop("think")  # this model has no thinking mode
            data, size, digest = await post_json(self.client, url, body)
        try:
            text = data["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise AIError("unexpected reply from ollama") from exc
        return Completion(
            data=parse_json_text(text),
            text=text,
            prompt_tokens=int(data.get("prompt_eval_count") or 0),
            completion_tokens=int(data.get("eval_count") or 0),
            bytes_sent=size,
            payload_sha256=digest,
        )
