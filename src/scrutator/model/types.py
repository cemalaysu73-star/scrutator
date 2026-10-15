from enum import Enum


class EntityType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    ASN = "asn"
    ORG = "org"


class ScopeState(str, Enum):
    """IN: may be investigated. LINKED: reached from an in-scope entity, enrich passively only.
    OUT: recorded, never investigated."""

    OUT = "out"
    LINKED = "linked"
    IN = "in"

    @property
    def rank(self) -> int:
        return {"out": 0, "linked": 1, "in": 2}[self.value]
