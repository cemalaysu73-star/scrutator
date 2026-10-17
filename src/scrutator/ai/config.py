import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

PROVIDERS = {"ollama", "openai", "anthropic"}
ROLES = ("planner", "verifier", "writer")
_AI_KEYS = {"mode", "redact", "max_steps", *ROLES}
_ROLE_KEYS = {"provider", "model", "base_url", "api_key_env"}


class AIMode(str, Enum):
    AUTO = "auto"
    OFF = "off"
    LOCAL = "local"
    CLOUD = "cloud"
    HYBRID = "hybrid"


@dataclass(frozen=True)
class RoleSpec:
    provider: str
    model: str
    base_url: str | None = None
    api_key_env: str | None = None

    def __post_init__(self) -> None:
        if self.provider not in PROVIDERS:
            raise ValueError(f"unknown provider {self.provider!r}; use one of {sorted(PROVIDERS)}")
        if not self.model.strip():
            raise ValueError("model must not be empty")


@dataclass(frozen=True)
class AIConfig:
    mode: AIMode = AIMode.AUTO
    roles: Mapping[str, RoleSpec] = field(default_factory=dict)
    redact: bool = False
    max_steps: int = 1000


def default_config_path() -> Path:
    return Path.home() / ".config" / "scrutator" / "config.toml"


def load_config(path: Path | None) -> AIConfig:
    """Read the [ai] table. A missing default file means defaults; a missing explicit file is an error."""
    target = path or default_config_path()
    if not target.exists():
        if path is not None:
            raise ValueError(f"config file not found: {path}")
        return AIConfig()
    data = tomllib.loads(target.read_text(encoding="utf-8")).get("ai", {})
    unknown = set(data) - _AI_KEYS
    if unknown:
        raise ValueError(f"unknown keys in [ai]: {sorted(unknown)}")
    roles: dict[str, RoleSpec] = {}
    for role in ROLES:
        if role not in data:
            continue
        section = data[role]
        extra = set(section) - _ROLE_KEYS
        if extra:
            raise ValueError(f"unknown keys in [ai.{role}]: {sorted(extra)}")
        roles[role] = RoleSpec(
            provider=section.get("provider", ""),
            model=section.get("model", ""),
            base_url=section.get("base_url"),
            api_key_env=section.get("api_key_env"),
        )
    return AIConfig(
        mode=AIMode(data.get("mode", "auto")),
        roles=roles,
        redact=bool(data.get("redact", False)),
        max_steps=int(data.get("max_steps", 1000)),
    )
