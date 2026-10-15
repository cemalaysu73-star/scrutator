from pydantic import BaseModel, ConfigDict, ValidationInfo, field_validator

from scrutator.model.canonical import canonicalize
from scrutator.model.types import EntityType, ScopeState


class Entity(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: EntityType
    value: str

    @field_validator("value")
    @classmethod
    def _canonicalize(cls, value: str, info: ValidationInfo) -> str:
        etype = info.data.get("type")
        if etype is None:
            return value
        return canonicalize(etype, value)

    @property
    def id(self) -> str:
        return f"{self.type.value}:{self.value}"


class Edge(BaseModel):
    model_config = ConfigDict(frozen=True)

    src: str
    rel: str
    dst: str
    evidence_ids: tuple[str, ...]


class StoredEntity(BaseModel):
    model_config = ConfigDict(frozen=True)

    entity: Entity
    state: ScopeState
