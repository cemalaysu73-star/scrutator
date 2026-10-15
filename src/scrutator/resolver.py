import dns.asyncresolver
import dns.resolver


class DnsResolver:
    """Thin dnspython wrapper. Missing names and records yield an empty list."""

    def __init__(self, nameservers: list[str] | None = None, timeout: float = 5.0) -> None:
        self._resolver = dns.asyncresolver.Resolver()
        if nameservers:
            self._resolver.nameservers = list(nameservers)
        self._resolver.lifetime = timeout

    async def lookup(self, name: str, rtype: str) -> list[str]:
        try:
            answer = await self._resolver.resolve(name, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        return [record.to_text() for record in answer]
