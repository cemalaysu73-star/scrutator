import asyncio
import time
from dataclasses import dataclass

import dns.asyncquery
import dns.asyncresolver
import dns.flags
import dns.message
import dns.rdatatype
import dns.resolver

NEGATIVE = frozenset({"nxdomain", "nodata"})
NXNAME = 128  # pseudo-type in an NSEC bitmap: "this name does not exist" (compact denial of existence)


def _denies_existence(error: dns.resolver.NoAnswer) -> bool:
    """True when a NOERROR/empty response is really a compact denial of existence: Cloudflare and
    others answer a missing name with NOERROR and an NSEC whose type bitmap lists NXNAME, instead of
    sending NXDOMAIN. An NSEC without NXNAME is an ordinary NODATA for a name that exists."""
    try:
        response = error.response()
    except KeyError:  # raised without a response (nothing to inspect)
        return False
    for rrset in response.authority:
        if rrset.rdtype != dns.rdatatype.NSEC:
            continue
        for rdata in rrset:
            for window, bitmap in rdata.windows:
                index, mask = divmod(NXNAME - window * 256, 8)
                if 0 <= index < len(bitmap) and bitmap[index] & (0x80 >> mask):
                    return True
    return False


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
    original contract (missing names and records yield an empty list).

    A scan resolves hundreds of names, so the resolver is a bounded pool: at most `max_in_flight` queries
    are on the wire at once, however many lookups wait. With `cache=True` it also remembers definite
    answers (records, NXDOMAIN, NODATA) for the life of the resolver, so a question asked twice in one scan
    goes out once; a timeout or SERVFAIL is never remembered."""

    def __init__(
        self, nameservers: list[str] | None = None, timeout: float = 5.0, *, max_in_flight: int = 128, cache: bool = False
    ) -> None:
        self._resolver = dns.asyncresolver.Resolver()
        if nameservers:
            self._resolver.nameservers = list(nameservers)
        self._resolver.lifetime = timeout
        # Ask for DNSSEC records: a recursive resolver sends the NSEC (and its NXNAME marker) only to DO queries.
        self._resolver.use_edns(0, dns.flags.DO, 1232)
        self._slots = asyncio.Semaphore(max_in_flight)
        self._memo: dict[tuple[str, str], DnsAnswer] | None = {} if cache else None
        self.cache_hits = 0

    async def query(self, name: str, rtype: str) -> DnsAnswer:
        if self._memo is not None:
            remembered = self._memo.get((name, rtype))
            if remembered is not None:
                self.cache_hits += 1
                return remembered
        async with self._slots:
            answer = await self._ask(name, rtype)
        if self._memo is not None and answer.status in ("answer", "nxdomain", "nodata"):
            self._memo[(name, rtype)] = answer
        return answer

    async def _ask(self, name: str, rtype: str) -> DnsAnswer:
        try:
            answer = await self._resolver.resolve(name, rtype)
        except dns.resolver.NXDOMAIN:
            return DnsAnswer("nxdomain")
        except dns.resolver.NoAnswer as error:
            return DnsAnswer("nxdomain" if _denies_existence(error) else "nodata")
        except dns.resolver.NoNameservers:
            return DnsAnswer("servfail")
        self._prefer(getattr(answer, "nameserver", None))
        records = tuple(record.to_text() for record in answer)
        return DnsAnswer("answer", records) if records else DnsAnswer("nodata")

    async def warm_up(self, timeout: float = 2.0, grace: float = 0.15) -> None:
        """Put the configured name servers in the order of how fast they answer. A dead first server in the
        system configuration otherwise costs a full timeout for every lookup that starts before one has
        answered, and a scan starts hundreds at once. Each server gets one query for the root's NS records,
        all at the same moment. The scan does not wait for a server that is slow or dead: once one has
        answered, the others get `grace` seconds to show they are as fast, and those that have not answered
        by then keep their place behind the ones that have."""
        servers = list(self._resolver.nameservers)
        if len(servers) < 2:
            return
        probes = {asyncio.ensure_future(self._probe(server, timeout)): index for index, server in enumerate(servers)}
        pending = set(probes)
        answered: list[tuple[float, int]] = []

        def collect(done) -> None:
            for task in done:
                latency = task.result()
                if latency is not None:
                    answered.append((latency, probes[task]))

        try:
            while pending and not answered:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                collect(done)
            if pending:
                done, pending = await asyncio.wait(pending, timeout=grace)
                collect(done)
        finally:
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        if not answered:
            return
        first = [index for _, index in sorted(answered)]
        self._resolver.nameservers = [servers[i] for i in first] + [servers[i] for i in range(len(servers)) if i not in first]

    @staticmethod
    async def _probe(server: str, timeout: float) -> float | None:
        started = time.perf_counter()
        try:
            await dns.asyncquery.udp(dns.message.make_query(".", "NS"), server, timeout=timeout)
        except Exception:  # noqa: BLE001 - a server that does not answer is only ranked last
            return None
        return time.perf_counter() - started

    def _prefer(self, nameserver: str | None) -> None:
        """Try the server that just answered first from now on. A dead first server in the system
        configuration otherwise costs a full timeout on every single lookup."""
        servers = self._resolver.nameservers
        if nameserver in servers and servers[0] != nameserver:
            self._resolver.nameservers = [nameserver, *(s for s in servers if s != nameserver)]

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
