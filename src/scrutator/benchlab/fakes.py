"""The fakes the labs are built from: a status-aware resolver, a router for mocked sources, and pack writers."""

import json
import re
from collections.abc import Callable
from pathlib import Path

import httpx
import yaml

from scrutator.packs import build_manifest
from scrutator.resolver import DnsAnswer

Handler = Callable[[httpx.Request], httpx.Response]


class StatusResolver:
    """`zone` maps (name, rtype) to a list of records, or to the string "NXDOMAIN" or "NODATA" to
    force that answer (a CNAME whose target does not exist makes the address lookup NXDOMAIN).
    A name that appears nowhere in the zone does not exist (NXDOMAIN); a name that exists but
    lacks the record type gives NODATA. `wildcards` maps a zone apex to the addresses its wildcard
    record gives any name under it that the zone does not hold. Pass `boom={(name, rtype): exception}`
    to make one lookup raise. Every question is kept in `calls`."""

    def __init__(self, zone=None, boom=None, wildcards=None):
        self.zone = {key: value if isinstance(value, str) else list(value) for key, value in (zone or {}).items()}
        self.boom = boom or {}
        self.wildcards = dict(wildcards or {})
        self.calls: list[tuple[str, str]] = []

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
        if not exists and rtype in ("A", "AAAA"):
            for apex, addresses in self.wildcards.items():
                if name.endswith("." + apex):
                    wanted = [a for a in addresses if (":" in a) == (rtype == "AAAA")]
                    return DnsAnswer("answer", tuple(wanted)) if wanted else DnsAnswer("nodata")
        return DnsAnswer("nodata" if exists else "nxdomain")

    async def lookup(self, name, rtype):
        return list((await self.query(name, rtype)).records)


class Router:
    """Routes for a MockTransport (or a respx side effect): the first route whose method, host and path match
    answers. A request no route matches fails like a host that does not exist."""

    def __init__(self) -> None:
        self.routes: list[tuple[str, str, re.Pattern, Callable]] = []
        self.calls: list[httpx.Request] = []

    def add(self, host: str, path: str, answer, *, regex: bool = False) -> None:
        pattern = re.compile(path if regex else re.escape(path) + r"\Z")
        self.routes.append(("GET", host, pattern, answer if callable(answer) else (lambda _request, _a=answer: _a)))

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        for method, host, pattern, answer in self.routes:
            if request.method == method and request.url.host == host and pattern.match(request.url.path):
                response = answer(request)
                return httpx.Response(response.status_code, headers=response.headers, content=response.content)
        raise httpx.ConnectError(f"no such host in the lab: {request.url.host}{request.url.path}", request=request)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)

    def add_rdap_ip(self, answer) -> None:
        """RDAP about an address, wherever the scan asks it: rdap.org, or (R6) the regional registry that holds a
        public address. `answer` sees the request; the address is the last path segment either way."""
        from scrutator.modules.rdap import RIR_SERVERS

        self.add("rdap.org", r"/ip/.*", answer, regex=True)
        for base in RIR_SERVERS:
            host, _, prefix = base.removeprefix("https://").partition("/")
            self.add(host, rf"/{re.escape(prefix)}ip/.*", answer, regex=True)


def provider(entry_id="example-dns", **over):
    entry = {
        "id": entry_id,
        "provider": "Example DNS",
        "category": "dns",
        "ns": ["dns.example.net"],
        "source": "https://docs.example.net/nameservers",
        "verified": True,
    }
    entry.update(over)
    return entry


def takeover(entry_id="example-pages", **over):
    entry = {
        "id": entry_id,
        "provider": "Example Pages",
        "cname": ["pages.example.net"],
        "status": "vulnerable",
        "dangling": "nxdomain",
        "source": "https://docs.example.net/custom-domains",
        "verified": True,
    }
    entry.update(over)
    return entry


def signal(entry_id="shared-ns-set", **over):
    entry = {
        "id": entry_id,
        "signal": "ns_set",
        "frequency": 0.2,
        "sample_size": 1000,
        "source": "https://example.net/corpus",
        "verified": True,
    }
    entry.update(over)
    return entry


def document(kind, entries, version="2026.10.1"):
    return {"schema": 1, "kind": kind, "version": version, "updated": "2026-10-16", "entries": entries}


def write_pack(directory: Path, name, kind, entries, *, version="2026.10.1", manifest=False):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(yaml.safe_dump(document(kind, entries, version)), encoding="utf-8")
    if manifest:
        write_manifest(directory)
    return directory


def write_manifest(directory: Path):
    (directory / "manifest.json").write_text(json.dumps(build_manifest(directory), indent=2, sort_keys=True) + "\n", encoding="utf-8")
