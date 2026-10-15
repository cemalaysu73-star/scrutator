from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Finding(BaseModel):
    """A claim. It cannot exist without at least one evidence id."""

    model_config = ConfigDict(frozen=True)

    claim: str
    entity_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...] = Field(min_length=1)
    confidence: Confidence
