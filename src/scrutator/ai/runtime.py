from collections.abc import Callable
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from scrutator.ai.generate import generate
from scrutator.ai.redact import Redactor
from scrutator.ai.types import AIError, Completion, LLMProvider
from scrutator.store import Store

T = TypeVar("T", bound=BaseModel)


def _restore(value: Any, redactor: Redactor) -> Any:
    if isinstance(value, str):
        return redactor.restore(value)
    if isinstance(value, list):
        return [_restore(v, redactor) for v in value]
    if isinstance(value, dict):
        return {k: _restore(v, redactor) for k, v in value.items()}
    return value


class AIRuntime:
    """Routes a role (planner, verifier, writer) to a provider. For non-local providers it
    pseudonymises the prompt when a redactor is set, restores the answer, and writes an
    egress record for every request that leaves the machine."""

    def __init__(self, providers: dict[str, LLMProvider], *, redactor: Redactor | None = None) -> None:
        self.providers = dict(providers)
        self.redactor = redactor
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.on_egress: Callable[[str, LLMProvider, Completion, bool], None] | None = None
        self._store: Store | None = None
        self._scan_id: int | None = None

    def bind(self, store: Store, scan_id: int) -> None:
        self._store = store
        self._scan_id = scan_id

    def has(self, *roles: str) -> bool:
        return all(role in self.providers for role in roles)

    async def generate(
        self, role: str, system: str, user: str, model: type[T], *, max_repairs: int = 2
    ) -> T:
        provider = self.providers.get(role)
        if provider is None:
            raise AIError(f"no provider configured for role {role!r}")
        redact = self.redactor is not None and not provider.is_local
        if redact:
            system, user = self.redactor.redact(system), self.redactor.redact(user)

        def on_call(call_role: str, prov: LLMProvider, completion: Completion) -> None:
            self.prompt_tokens += completion.prompt_tokens
            self.completion_tokens += completion.completion_tokens
            if not prov.is_local:
                self._log_egress(call_role, prov, completion, redact)

        result = await generate(
            provider, system, user, model, role=role, max_repairs=max_repairs, on_call=on_call
        )
        if redact:
            try:
                result = type(result).model_validate(_restore(result.model_dump(), self.redactor))
            except ValidationError:
                pass
        return result

    def _log_egress(self, role: str, provider: LLMProvider, completion: Completion, redacted: bool) -> None:
        if self.on_egress is not None:
            self.on_egress(role, provider, completion, redacted)
        if self._store is not None and self._scan_id is not None:
            self._store.record_egress(
                self._scan_id,
                role=role,
                provider=provider.name,
                model=provider.model,
                host=provider.host,
                bytes_sent=completion.bytes_sent,
                payload_sha256=completion.payload_sha256,
                redacted=redacted,
            )

    def describe(self) -> dict[str, Any]:
        return {
            "providers": {
                role: {"provider": p.name, "model": p.model, "local": p.is_local}
                for role, p in self.providers.items()
            },
            "redacted": self.redactor is not None,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
        }
