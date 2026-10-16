"""What an attribution is made of: signals with a weight, a score, a band.

The weights are chosen by hand. They are not measured, and nothing here claims they are
calibrated to the real world; the planted lab (tests/attrlab.py) shows the scoring behaves as
designed on the cases its author thought of. A knowledge pack can lower a signal's weight with a
measured frequency (see engine.py), which is how a real measurement should enter.
"""

from dataclasses import dataclass

RULESET_VERSION = 1

BANDS = ("confirmed", "probable", "possible", "unlikely")
CONFIRMED_AT = 0.90
PROBABLE_AT = 0.70
POSSIBLE_AT = 0.35

# kind -> (weight when nothing discounts it, one line saying what the evidence is)
SIGNALS: dict[str, tuple[float, str]] = {
    "ns_in_scope": (0.90, "the name is delegated to a name server under an in-scope domain"),
    "mx_in_scope": (0.70, "its mail is received by a host under an in-scope domain"),
    "spf_in_scope": (0.60, "its SPF record includes a name under an in-scope domain"),
    "cert_san": (0.60, "one certificate lists both an in-scope name and this name"),
    "rdap_registrant": (0.60, "its registrant organisation is the same as an in-scope domain's"),
    "shared_ns": (0.50, "it uses the same name servers as an in-scope zone, and they are not a shared provider"),
    "shared_mx": (0.40, "it receives mail on a host an in-scope name also uses, and that host is not a shared provider"),
    "network_owner": (0.35, "its address is in a network with the same owner or AS as an in-scope address, and that is not a shared provider"),
    "scope_uses": (0.20, "an in-scope name points its name servers, mail or SPF at it, and it is not a shared provider"),
    "cert_issuer": (0.10, "it and an in-scope name use certificates from the same issuer, and that issuer is not a common CA"),
}


@dataclass(frozen=True)
class Signal:
    kind: str
    weight: float  # what counts, after discounts
    raw_weight: float  # what the kind is worth before any discount
    detail: str
    evidence_ids: tuple[str, ...]
    note: str = ""  # why the weight is lower than the raw weight, if it is

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "weight": self.weight,
            "raw_weight": self.raw_weight,
            "detail": self.detail,
            "evidence_ids": list(self.evidence_ids),
            "note": self.note,
        }


def combine(weights: list[float]) -> float:
    """Independent signals add up as 1 - product(1 - w): each one removes part of the remaining
    doubt, none can push the score past 1, and many weak ones never reach a strong one."""
    remaining = 1.0
    for weight in weights:
        remaining *= 1.0 - weight
    return round(1.0 - remaining, 4)


# Evidence only the owner (or someone it runs services for) can produce: its own name servers,
# mail host or SPF record, the same registrant. A shared certificate, name servers, network or mail
# host can just as well be a partner's, a customer's or a host's, so on its own it never gets past
# `possible`. This is the rule the planted lab showed was needed: without it, a partner with a
# co-branded certificate and the same small DNS operator scored 0.80.
OWNERSHIP = frozenset({"ns_in_scope", "mx_in_scope", "spf_in_scope", "rdap_registrant"})


def band_for(score: float, kinds: set[str] | frozenset[str]) -> str:
    """The band for a score and the kinds of signal that count toward it. `confirmed` needs a high
    score from at least two different kinds, so no single observation can confirm anything; both it
    and `probable` need an ownership signal."""
    if kinds & OWNERSHIP:
        if score >= CONFIRMED_AT and len(kinds) >= 2:
            return "confirmed"
        if score >= PROBABLE_AT:
            return "probable"
    if score >= POSSIBLE_AT:
        return "possible"
    return "unlikely"


def band_rank(band: str) -> int:
    """Higher is stronger: confirmed 3 ... unlikely 0."""
    return len(BANDS) - 1 - BANDS.index(band)
