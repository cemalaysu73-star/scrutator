from dataclasses import dataclass

import dns.asyncresolver
import dns.resolver

NEGATIVE = frozenset({"nxdomain", "nodata"})


@dataclass(frozen=True)
class DnsAnswer:
    """What a lookup returned, including why it returned nothing.

    status is one of: `answer` (records follow), `nxdomain` (the name does not exist),
    `nodata` (the name exists but has no record of that type), `servfail` (no server gave a
    usable answer) or `empty` (a resolver that cannot say why it returned nothing)."""

    status: str
    records: tuple[str, ...] = ()

    @property
    def negative(self) -> bool:
        """A definite "no": only these may be recorded as evidence of absence."""
        return self.status in NEGATIVE

    def payload(self) -> str:
        """The text stored as evidence. Records are one per line; a definite negative is the
        single word NXDOMAIN or NODATA. (A record can never be mistaken for these: TXT text is
        quoted and host names end in a dot.)"""
        if self.status == "answer":
            return "\n".join(self.records)
        if self.status == "nxdomain":
            return "NXDOMAIN"
        if self.status == "nodata":
            return "NODATA"
        return ""


def parse_payload(payload: str) -> DnsAnswer:
    """The inverse of DnsAnswer.payload()."""
    if payload == "NXDOMAIN":
        return DnsAnswer("nxdomain")
    if payload == "NODATA":
        return DnsAnswer("nodata")
    records = tuple(line for line in payload.splitlines() if line.strip())
    return DnsAnswer("answer", records) if records else DnsAnswer("empty")


class DnsResolver:
    """Thin dnspython wrapper. `query` says why a lookup was empty; `lookup` keeps the
    original contract (missing names and records yield an empty list)."""

    def __init__(self, nameservers: list[str] | None = None, timeout: float = 5.0) -> None:
        self._resolver = dns.asyncresolver.Resolver()
        if nameservers:
            self._resolver.nameservers = list(nameservers)
        self._resolver.lifetime = timeout

    async def query(self, name: str, rtype: str) -> DnsAnswer:
        try:
            answer = await self._resolver.resolve(name, rtype)
        except dns.resolver.NXDOMAIN:
            return DnsAnswer("nxdomain")
        except dns.resolver.NoAnswer:
            return DnsAnswer("nodata")
        except dns.resolver.NoNameservers:
            return DnsAnswer("servfail")
        records = tuple(record.to_text() for record in answer)
        return DnsAnswer("answer", records) if records else DnsAnswer("nodata")

    async def lookup(self, name: str, rtype: str) -> list[str]:
        return list((await self.query(name, rtype)).records)


async def lookup_status(resolver, name: str, rtype: str) -> DnsAnswer:
    """Ask a resolver for a status-aware answer. A resolver that only has the older
    `lookup(name, rtype) -> list[str]` still works: an empty list becomes `empty`, which is
    never treated as a definite negative."""
    query = getattr(resolver, "query", None)
    if callable(query):
        return await query(name, rtype)
    records = await resolver.lookup(name, rtype)
    return DnsAnswer("answer", tuple(records)) if records else DnsAnswer("empty")
