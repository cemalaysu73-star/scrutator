from collections.abc import Callable
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from scrutator.ai.types import AIOutputError, Completion, LLMProvider

T = TypeVar("T", bound=BaseModel)


async def generate(
    provider: LLMProvider,
    system: str,
    user: str,
    model: type[T],
    *,
    role: str = "planner",
    max_repairs: int = 2,
    on_call: Callable[[str, LLMProvider, Completion], None] | None = None,
) -> T:
    """Ask for output matching `model`. Invalid output is sent back with the validation
    error up to `max_repairs` times; after that AIOutputError is raised. Callers treat that
    as 'the model could not do this' and fall back to deterministic behaviour."""
    schema = model.model_json_schema()
    prompt = user
    last_error = ""
    for _ in range(max_repairs + 1):
        completion = await provider.complete_json(system, prompt, schema)
        if on_call is not None:
            on_call(role, provider, completion)
        try:
            return model.model_validate(completion.data)
        except (ValidationError, ValueError) as exc:
            last_error = str(exc)
            prompt = (
                f"{user}\n\nYour previous reply was rejected: {last_error[:500]}\n"
                "Reply with JSON that matches the schema exactly and nothing else."
            )
    raise AIOutputError(
        f"{provider.name}/{provider.model} produced no valid {model.__name__}: {last_error[:200]}"
    )
