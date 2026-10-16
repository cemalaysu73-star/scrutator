"""A status-aware resolver for tests: it knows why an answer is empty."""

from scrutator.resolver import DnsAnswer


class StatusResolver:
    """`zone` maps (name, rtype) to a list of records, or to the string "NXDOMAIN" or "NODATA" to
    force that answer (a CNAME whose target does not exist makes the address lookup NXDOMAIN).
    A name that appears nowhere in the zone does not exist (NXDOMAIN); a name that exists but
    lacks the record type gives NODATA. Pass `boom={(name, rtype): exception}` to make one
    lookup raise."""

    def __init__(self, zone=None, boom=None):
        self.zone = {key: value if isinstance(value, str) else list(value) for key, value in (zone or {}).items()}
        self.boom = boom or {}
        self.calls = []

    async def query(self, name, rtype):
        self.calls.append((name, rtype))
        if (name, rtype) in self.boom:
            raise self.boom[(name, rtype)]
        records = self.zone.get((name, rtype))
        if isinstance(records, str):
            return DnsAnswer(records.lower())
        if records:
            return DnsAnswer("answer", tuple(records))
        known = {n for n, _ in self.zone}
        # a name that has any record, or sits above one, exists
        exists = name in known or any(n.endswith("." + name) for n in known)
        return DnsAnswer("nodata" if exists else "nxdomain")

    async def lookup(self, name, rtype):
        return list((await self.query(name, rtype)).records)
