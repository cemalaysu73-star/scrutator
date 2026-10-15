from typing import Literal

from pydantic import BaseModel, Field


class Ranking(BaseModel):
    choices: list[int] = Field(max_length=50)
    hypothesis: str = Field(default="", max_length=300)


class Settlement(BaseModel):
    id: int
    status: Literal["confirmed", "refuted"]
    evidence_refs: list[str] = Field(min_length=1, max_length=8)


class SettleResult(BaseModel):
    settled: list[Settlement] = Field(default_factory=list, max_length=10)
