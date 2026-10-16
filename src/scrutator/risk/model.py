import hashlib
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from scrutator.model import Confidence, Finding


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3}[self.value]


class Risk(BaseModel):
    """A hygiene or dependency finding. Like a Finding it cannot exist without evidence: at
    least one evidence id is required. `explanation` states only what the cited evidence shows;
    `remediation` is general advice and makes no claim about the target."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    severity: Severity
    category: Literal["risk", "analyst"]
    title: str
    entity_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...] = Field(min_length=1)
    explanation: str
    remediation: str
    confidence: Confidence

    @property
    def fingerprint(self) -> str:
        """Stable across scans: the rule and the entities, not the evidence or the wording.
        A later ticketing integration uses it to update one ticket instead of opening a new one."""
        text = self.rule_id + "\n" + "\n".join(sorted(self.entity_ids))
        return hashlib.sha256(text.encode()).hexdigest()[:32]

    @property
    def sort_key(self) -> tuple:
        return (-self.severity.rank, self.rule_id, self.entity_ids)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "category": self.category,
            "title": self.title,
            "entity_ids": list(self.entity_ids),
            "evidence_ids": list(self.evidence_ids),
            "explanation": self.explanation,
            "remediation": self.remediation,
            "confidence": self.confidence.value,
            "fingerprint": self.fingerprint,
        }

    def as_finding(self) -> Finding:
        """The claim form handed to the AI writer, so any statement about a risk is verified
        against the same evidence as every other finding."""
        return Finding(
            claim=f"Risk ({self.severity.value}): {self.title}. {self.explanation}",
            entity_ids=self.entity_ids,
            evidence_ids=self.evidence_ids,
            confidence=self.confidence,
        )


def severity_at_least(value: str, threshold: str) -> bool:
    return Severity(value).rank >= Severity(threshold).rank
