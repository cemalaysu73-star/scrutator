"""A scripted stand-in for an LLM provider, used by many tests."""

import json

from scrutator.ai.types import Completion

NOT_JSON = object()


class ScriptedProvider:
    def __init__(self, responses=(), *, name="fake", model="fake-model", is_local=True, responder=None):
        self._responses = list(responses)
        self._responder = responder
        self.name = name
        self.model = model
        self.is_local = is_local
        self.host = "127.0.0.1:11434" if is_local else "api.fake.test"
        self.calls: list[dict] = []

    async def complete_json(self, system, user, schema):
        self.calls.append({"system": system, "user": user, "schema": schema})
        item = self._responder(system, user, schema) if self._responder else self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        data = None if item is NOT_JSON else item
        text = "garbage" if item is NOT_JSON else json.dumps(item)
        sent = (system + user).encode()
        return Completion(
            data=data,
            text=text,
            prompt_tokens=len(sent) // 4,
            completion_tokens=len(text) // 4,
            bytes_sent=len(sent),
            payload_sha256="0" * 64,
        )
