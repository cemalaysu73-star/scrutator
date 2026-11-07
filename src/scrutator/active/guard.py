"""The guardrails: which addresses are never touched, and how much one scan may do.

Everything here is a pure function or a counter. Nothing opens a connection.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from dataclasses import dataclass

RELAXABLE = frozenset({"loopback", "documentation"})  # what a test may allow; no command-line option reaches this


@dataclass(frozen=True)
class Limits:
    """What one active run may do. Recorded in the signed audit log before the first connection."""

    max_connections: int = 60  # every connection opened, whatever for: connect checks, handshakes and requests
    concurrency: int = 4
    connect_timeout: float = 4.0
    banner_timeout: float = 2.0
    handshake_timeout: float = 5.0
    http_timeout: float = 6.0
    rate_per_second: float = 8.0  # new connections a second, over the whole run
    max_names_per_ip: int = 3  # in-scope names a TLS handshake and an HTTP request are made for, per address
    tcp_share: float = 0.7  # the share of the cap the connect checks may plan for; the rest is for handshakes and requests
    deadline_s: float = 120.0  # the whole active phase

    def __post_init__(self) -> None:
        if not 1 <= self.max_connections <= 500:
            raise ValueError("max_connections must be between 1 and 500")
        if not 1 <= self.concurrency <= 16:
            raise ValueError("concurrency must be between 1 and 16")
        if not 0.5 <= self.connect_timeout <= 15 or not 0.2 <= self.banner_timeout <= 5:
            raise ValueError("timeouts out of range")
        if not 0.5 <= self.rate_per_second <= 50:
            raise ValueError("rate_per_second must be between 0.5 and 50")

    @property
    def tcp_budget(self) -> int:
        return max(1, int(self.max_connections * self.tcp_share))

    def record(self) -> dict:
        return {
            "max_connections": self.max_connections, "concurrency": self.concurrency,
            "connect_timeout_s": self.connect_timeout, "banner_timeout_s": self.banner_timeout,
            "handshake_timeout_s": self.handshake_timeout, "http_timeout_s": self.http_timeout,
            "rate_per_second": self.rate_per_second, "max_names_per_ip": self.max_names_per_ip,
            "tcp_budget": self.tcp_budget, "deadline_s": self.deadline_s,
        }


def refusal(address: str, relax: frozenset[str] = frozenset()) -> str:
    """Why `address` is never probed, or "" when it may be. Only a public IPv4 address passes: a public name that
    resolves to a private, loopback, link-local (cloud metadata is 169.254.169.254), shared, documentation or otherwise
    reserved address is refused whatever the name is, because it would turn the scan into a request to the tester's or
    the client's internal network (SSRF through DNS)."""
    try:
        ip = ipaddress.ip_address(str(address).strip())
    except ValueError:
        return "not an IP address"
    if ip.version != 4:
        return "IPv6 addresses are not probed in this version"
    if ip.is_loopback:
        return "" if "loopback" in relax else "loopback address"
    if ip.is_link_local:
        return "link-local address (includes the cloud metadata address)"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_unspecified or str(ip) == "255.255.255.255":
        return "unspecified or broadcast address"
    if any(ip in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")):
        return "" if "documentation" in relax else "documentation address (RFC 5737)"
    if ip in ipaddress.ip_network("100.64.0.0/10"):
        return "shared address space (RFC 6598)"
    if ip in ipaddress.ip_network("240.0.0.0/4") or ip in ipaddress.ip_network("198.18.0.0/15"):
        return "reserved address"
    if ip.is_private:
        return "private address"
    if not ip.is_global:
        return "reserved address"
    return ""


_ASN = re.compile(r"(?i)^as(\d{1,10})$")


def shared_platform(packs, *, address: str, asns=(), hosts=(), netnames=()):
    """The first shared-platform entry that recognises the address and the signal that did: `(entry, "asn AS13335")`, or
    None. `asns` are AS numbers announcing the address, `hosts` the CNAME targets of the in-scope names that resolve to
    it and the reverse names a passive source saw, `netnames` the network names a registry gave for it."""
    ip = ipaddress.ip_address(address)
    numbers = set()
    for value in asns:
        match = _ASN.match(str(value).strip())
        if match:
            numbers.add(int(match.group(1)))
        elif str(value).strip().isdigit():
            numbers.add(int(str(value).strip()))
    names = [str(h).strip().lower().rstrip(".") for h in hosts if str(h).strip()]
    labels = [" ".join(str(n).lower().split()) for n in netnames if str(n).strip()]
    for entry in packs.shared:
        for net in entry.cidrs:
            if ip in ipaddress.ip_network(net):
                return entry, f"address in {net}"
        hit = sorted(numbers & set(entry.asn))
        if hit:
            return entry, f"announced by AS{hit[0]}"
        for pattern in entry.hosts:
            for name in names:
                if name == pattern or name.endswith("." + pattern):
                    return entry, f"host name {name}"
        for pattern in entry.netname:
            for label in labels:
                if pattern in label:
                    return entry, f"network name {label[:60]}"
    return None


class Budget:
    """The connection budget of one run: every connection is taken from it before it is opened, so the cap is enforced in
    one place whatever the probe, and a run can never exceed it however the phases interleave."""

    def __init__(self, limits: Limits, *, clock=time.monotonic, sleep=asyncio.sleep) -> None:
        self.limits = limits
        self.used = 0
        self._clock, self._sleep = clock, sleep
        self._next = clock()
        self._lock = asyncio.Lock()

    @property
    def exhausted(self) -> bool:
        return self.used >= self.limits.max_connections

    async def take(self) -> bool:
        """Reserve one connection and wait for the rate limit's turn. False when the cap is reached (nothing reserved)."""
        async with self._lock:
            if self.exhausted:
                return False
            self.used += 1
            now = self._clock()
            wait = self._next - now
            self._next = max(now, self._next) + 1.0 / self.limits.rate_per_second
        if wait > 0:
            await self._sleep(wait)
        return True
