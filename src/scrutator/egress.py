"""Where the data-source HTTP client may connect: a fixed set of source hosts, and nothing a response can talk it into.

Every request the modules (and `verify --replay`) make goes through `EgressGuard`, including each redirect hop and
any URL a source hands back (Common Crawl's index list names the URL of its search API, for example). A request is
sent only when it is

- `https` on the default port, to a host name (never an IP literal, never userinfo), and
- to one of the source hosts below, or to a host an RDAP redirect led to: `rdap.org` is a bootstrap service that
  sends a query on to the registry's or the RIR's RDAP server, which cannot be listed in advance. Such a host must
  also resolve only to public addresses (not loopback, private, link-local, reserved or multicast), checked before
  the request. Only RDAP servers may redirect off the list; a redirect anywhere else from any other source is refused.

What this does not cover: a host on the list could itself be compromised, and an RDAP server's address is checked
once per scan, before its first request, so a name that changes its answer between the check and the connection (DNS rebinding)
is not caught. The target itself is never on the list, so a redirect can never turn a passive scan into contact
with the organisation under investigation. (The opt-in brand and organisation-exposure modules, which do read the
organisation's own site, use a separate client and guard: scrutator/web.py.)"""

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable

import httpx

# The hosts the built-in modules query (keyless sources and the keyed ones).
SOURCE_HOSTS = frozenset(
    {
        "crt.sh",
        "rdap.org",
        # the regional registries' own RDAP servers: public addresses are asked of the one that holds them
        "rdap.arin.net",
        "rdap.db.ripe.net",
        "rdap.apnic.net",
        "rdap.lacnic.net",
        "rdap.afrinic.net",
        "ip.thc.org",
        "stat.ripe.net",
        "web.archive.org",
        "index.commoncrawl.org",
        "api.certspotter.com",
        "api.hackertarget.com",
        "api.subdomain.center",
        "urlscan.io",
        "api.mnemonic.no",
        "internetdb.shodan.io",
        "www.virustotal.com",
        "api.securitytrails.com",
        "api.shodan.io",
        # `scrutator exposure` (public repositories of named organisations) and `scan --org` (GitHub organisation sources)
        "api.github.com",
        # `scan --org`: the organisation-scoped sources (docs/organisation.md). Keyless unless noted.
        "api.gleif.org",  # company records (LEI)
        "query.wikidata.org",  # Wikidata SPARQL
        "haveibeenpwned.com",  # breach metadata by domain (keyless breaches endpoint only)
        "registry.npmjs.org",  # npm packages and scopes
        "pypi.org",  # PyPI project metadata
        "hub.docker.com",  # Docker Hub namespaces
        "crates.io",  # crates.io crates
        "rubygems.org",  # RubyGems gems
        "api.nuget.org",  # NuGet registration
        "gitlab.com",  # GitLab public groups
        "public.api.bsky.app",  # Bluesky handle resolution
    }
)
# Hosts whose redirects may leave the list: the RDAP bootstrap, and (once a redirect reached one) RDAP servers,
# which refer a query on to another registry.
REDIRECTORS = frozenset({"rdap.org"})

# The only connections that are not HTTP: (host, port) pairs a module may open a raw TCP connection to. One today: crt.sh's
# public certificate database (scrutator.pgwire, the crt.sh module's fallback when its web search fails). Host and port
# are fixed in code, never read from a response or a bundle; `check_tcp` is called by pgwire before it connects, so no
# caller can reach another endpoint through it. Every connection leaves a trace in the scan: an evidence record
# `PGSQL crt.sh:5432/...` when it answered, or an `error` record of the crtsh module naming the database when it did not.
TCP_ENDPOINTS = frozenset({("crt.sh", 5432)})


def check_tcp(host: str, port: int) -> None:
    """Raise EgressDenied unless (host, port) is one of TCP_ENDPOINTS. Nothing is resolved or sent."""
    if (str(host).lower().rstrip("."), int(port)) not in TCP_ENDPOINTS:
        raise EgressDenied(f"egress refused: {host}:{port} is not an allowed TCP endpoint", request=httpx.Request("GET", "https://invalid.invalid/"))

Resolve = Callable[[str], Awaitable[list[str]]]


class EgressDenied(httpx.RequestError):
    """A request the egress policy does not allow. Nothing was sent."""


async def _system_resolve(host: str) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    return sorted({info[4][0] for info in infos})


def _ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


class EgressGuard:
    """Request and response hooks for an httpx client. One guard per client; it remembers the RDAP servers that
    redirects reached, so a referral chain between registries can continue."""

    def __init__(self, hosts: frozenset[str] = SOURCE_HOSTS, *, resolve: Resolve | None = None) -> None:
        self.hosts = hosts
        self._resolve = resolve or _system_resolve
        self._redirect_targets: set[str] = set()  # hosts an allowed redirect pointed at
        self._public: set[str] = set()  # referral hosts that resolved to public addresses only: checked once per guard
        self._redirectors: set[str] = set(REDIRECTORS)

    @staticmethod
    def _shape_problem(url: httpx.URL) -> str:
        if url.scheme != "https":
            return f"{url.scheme} is not allowed (https only)"
        if url.port not in (None, 443):
            return f"port {url.port} is not allowed"
        if url.userinfo:
            return "credentials in a URL are not allowed"
        host = url.host
        if not host or _ip_literal(host):
            return f"{host or 'an empty host'} is not a host name"
        if "." not in host.strip(".") or host.endswith((".local", ".localhost", ".internal", ".lan", ".home.arpa")) or host == "localhost":
            return f"{host} is a local name"
        return ""

    async def on_request(self, request: httpx.Request) -> None:
        problem = self._shape_problem(request.url)
        host = request.url.host.lower()
        if not problem and host not in self.hosts:
            if host not in self._redirect_targets:
                problem = f"{host} is not a source host"
            elif host not in self._public:
                try:
                    addresses = await self._resolve(host)
                except OSError as exc:
                    raise EgressDenied(f"egress refused: cannot resolve {host}: {exc}", request=request) from exc
                bad = [a for a in addresses if not ipaddress.ip_address(a.split("%")[0]).is_global]
                if not addresses or bad:
                    problem = f"{host} resolves to a non-public address ({(bad or ['nothing'])[0]})"
                else:
                    self._public.add(host)  # a failure is never remembered; a pass is, for the life of this guard
        if problem:
            raise EgressDenied(f"egress refused: {problem}", request=request)

    async def on_response(self, response: httpx.Response) -> None:
        # runs before the client builds the next request of a redirect, so the target is read from Location
        if not response.has_redirect_location:
            return
        try:
            url = response.request.url.join(response.headers["Location"])
        except (httpx.InvalidURL, ValueError) as exc:
            raise EgressDenied(f"egress refused: unusable redirect: {exc}", request=response.request) from exc
        origin = response.request.url.host.lower()
        host = url.host.lower()
        target = httpx.Request("GET", url)
        problem = self._shape_problem(url)
        if not problem and host not in self.hosts:
            if origin not in self._redirectors:
                problem = f"{origin} redirected to {host}, which is not a source host"
            else:
                self._redirect_targets.add(host)
                self._redirectors.add(host)  # an RDAP server may refer the query on to another registry
        if problem:
            await response.aclose()
            raise EgressDenied(f"egress refused: {problem}", request=target)

    def hooks(self) -> dict:
        return {"request": [self.on_request], "response": [self.on_response]}
