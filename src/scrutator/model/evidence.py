import hashlib
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict


class Evidence(BaseModel):
    """Immutable raw record of what a source returned. The id is a hash of
    (source, request, payload), so identical observations are stored once."""

    model_config = ConfigDict(frozen=True)

    id: str
    source: str
    request: str
    payload: str
    collected_at: str

    @classmethod
    def create(
        cls, source: str, request: str, payload: str, collected_at: str | None = None
    ) -> "Evidence":
        stamp = collected_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
        digest = hashlib.sha256(f"{source}\n{request}\n{payload}".encode()).hexdigest()
        return cls(id=digest, source=source, request=request, payload=payload, collected_at=stamp)
