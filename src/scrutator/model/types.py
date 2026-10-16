from enum import Enum


class EntityType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    ASN = "asn"
    ORG = "org"


class ScopeState(str, Enum):
    """IN: may be investigated. CANDIDATE: the attribution engine found evidence that it may belong
    to the organisation; passive lookups only, until the user promotes it. LINKED: reached from an
    in-scope or candidate entity, enrich passively only. OUT: recorded, never investigated."""

    OUT = "out"
    LINKED = "linked"
    CANDIDATE = "candidate"
    IN = "in"

    @property
    def rank(self) -> int:
        return {"out": 0, "linked": 1, "candidate": 2, "in": 3}[self.value]
