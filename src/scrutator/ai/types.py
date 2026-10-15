from dataclasses import dataclass
from typing import Any, Protocol


class AIError(Exception):
    """A model endpoint failed or is misconfigured."""


class AIOutputError(AIError):
    """The model kept returning output that does not match the requested schema."""


class EgressError(AIError):
    """A request would send data somewhere the current mode does not allow."""


@dataclass(frozen=True)
class Completion:
    data: Any  # parsed JSON, or None when the reply was not parseable
    text: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    bytes_sent: int = 0
    payload_sha256: str = ""


@dataclass(frozen=True)
class Runtime:
    """A model server found on this machine."""

    kind: str  # "ollama" or "openai" (any OpenAI-compatible server)
    base_url: str
    models: tuple[str, ...]


class LLMProvider(Protocol):
    name: str
    model: str
    is_local: bool
    host: str

    async def complete_json(self, system: str, user: str, schema: dict[str, Any]) -> Completion: ...
