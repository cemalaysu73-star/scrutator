"""The client for the two opt-in modules that contact more than the public data sources: brand presence (`scan --brand`)
and organisation exposure (`scrutator exposure`).

A passive scan never contacts the organisation under investigation. These modules do, a little, and only when asked:
they read a few pages of the organisation's own website, and brand presence asks public profile pages of platforms the
organisation links to whether a handle exists. `WebGuard` decides every request:

- `https` on the default port, to a host name (never an IP literal, userinfo or a local name), and
- either a platform host named by the knowledge packs (`platforms`), or a host inside the scope that resolves only to
  public addresses (checked before the first request to it; DNS rebinding between the check and the connection is
  the same documented limit as for RDAP referrals).

The client never follows a redirect by itself: a module follows one hop at a time, so every hop meets the guard.
`Robots` reads robots.txt the standard way (`urllib.robotparser`) for the user agent `scrutator`; a robots.txt that
cannot be read for a reason other than "not there" (404/410) counts as "disallow everything", the conservative
reading. `Pacer`s keep it to one request a second per host.
"""

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from html.parser import HTMLParser
from typing import AsyncIterator
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser

import httpx

from scrutator import __version__
from scrutator.egress import EgressDenied, EgressGuard
from scrutator.pacing import Pacer

USER_AGENT = f"scrutator/{__version__} (brand and exposure checks; robots.txt honoured)"
ROBOTS_AGENT = "scrutator"
MAX_BODY = 2 * 1024 * 1024  # a page is read up to this many bytes; links past it are not seen
MAX_LINKS = 500
MAX_ROBOTS = 64 * 1024
MAX_HOPS = 3

Resolve = Callable[[str], Awaitable[list[str]]]


async def _system_resolve(host: str) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    return sorted({info[4][0] for info in infos})


class WebGuard:
    """Request hook for the web client (see the module docstring)."""

    def __init__(self, in_scope: Callable[[str], bool], platform_hosts: frozenset[str] = frozenset(), *, resolve: Resolve | None = None) -> None:
        self.in_scope = in_scope
        self.platform_hosts = frozenset(h.lower() for h in platform_hosts)
        self._resolve = resolve or _system_resolve
        self._public: set[str] = set()

    async def on_request(self, request: httpx.Request) -> None:
        problem = EgressGuard._shape_problem(request.url)
        host = request.url.host.lower()
        if not problem and host not in self.platform_hosts:
            if not self.in_scope(host):
                problem = f"{host} is neither in scope nor a platform host"
            elif host not in self._public:
                try:
                    addresses = await self._resolve(host)
                except OSError as exc:
                    raise EgressDenied(f"egress refused: cannot resolve {host}: {exc}", request=request) from exc
                bad = [a for a in addresses if not ipaddress.ip_address(a.split("%")[0]).is_global]
                if not addresses or bad:
                    problem = f"{host} resolves to a non-public address ({(bad or ['nothing'])[0]})"
                else:
                    self._public.add(host)
        if problem:
            raise EgressDenied(f"egress refused: {problem}", request=request)

    def hooks(self) -> dict:
        return {"request": [self.on_request]}


@asynccontextmanager
async def open_web(guard: WebGuard, *, transport: httpx.AsyncBaseTransport | None = None) -> AsyncIterator[httpx.AsyncClient]:
    """The web client: no redirects followed, no retries (a refused request is an answer), short timeouts."""
    from scrutator import proxy

    async with httpx.AsyncClient(
        transport=transport,
        proxy=proxy.httpx_proxy() if transport is None else None,  # a test's own transport is never proxied
        timeout=httpx.Timeout(20.0, connect=10.0),
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT},
        event_hooks=guard.hooks(),
    ) as client:
        yield client


class Pacers:
    """One `Pacer` per host: at most one request a second to any single host."""

    def __init__(self, per_second: float = 1.0) -> None:
        self.per_second = per_second
        self._by_host: dict[str, Pacer] = {}

    async def take(self, url: str) -> None:
        host = (urlsplit(url).hostname or "").lower()
        await self._by_host.setdefault(host, Pacer(1, self.per_second)).take()


def robots_allows(status: int | None, text: str, url: str) -> bool:
    """Whether robots.txt (its HTTP status and text, as recorded) lets the `scrutator` agent fetch `url`. A pure
    function, so the decision can be re-derived from the evidence."""
    if status in (404, 410):
        return True
    if status is None or not 200 <= status < 300:
        return False
    parser = RobotFileParser()
    parser.parse(text.splitlines())
    return parser.can_fetch(ROBOTS_AGENT, url)


class _Links(HTMLParser):
    def __init__(self, base: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base, self.links = base, []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag not in ("a", "link") or len(self.links) >= MAX_LINKS:
            return
        values = dict(attrs)
        href = values.get("href")
        if not href or (tag == "link" and "me" not in str(values.get("rel", "")).lower().split()):
            return
        try:
            absolute = urljoin(self.base, href.strip())
            parts = urlsplit(absolute)
        except ValueError:
            return
        if parts.scheme in ("http", "https") and parts.hostname and len(absolute) <= 300:
            self.links.append(absolute)


def page_links(html: str, base: str) -> list[str]:
    """Absolute http(s) links of a page (`<a href>` and `<link rel="me">`), in order, without duplicates."""
    parser = _Links(base)
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # noqa: BLE001 - a broken page yields what was read before the break
        pass
    return list(dict.fromkeys(parser.links))


async def read_text(response: httpx.Response, limit: int = MAX_BODY) -> str:
    """The body as text, read up to `limit` bytes."""
    data = response.content[:limit]
    return data.decode(response.encoding or "utf-8", errors="replace")


async def get_following(client: httpx.AsyncClient, url: str, pacers: Pacers, allowed: Callable[[str], bool]) -> tuple[httpx.Response | None, list[str], str]:
    """GET `url`, following at most MAX_HOPS redirects, each only if `allowed(next_url)`. Returns the last response
    (None if the first request failed), the URLs visited, and why it stopped early ("" when it did not)."""
    visited: list[str] = []
    current = url
    for _ in range(MAX_HOPS + 1):
        visited.append(current)
        await pacers.take(current)
        response = await client.get(current)
        if not response.has_redirect_location:
            return response, visited, ""
        try:
            target = str(response.url.join(response.headers["Location"]))
        except (httpx.InvalidURL, ValueError):
            return response, visited, "unusable redirect"
        if not allowed(target):
            return response, visited, f"redirect to {urlsplit(target).hostname or target} not followed: outside the scope"
        current = target
    return response, visited, f"more than {MAX_HOPS} redirects"


def profile_hosts(packs) -> frozenset[str]:
    """The hosts of the profile pages brand presence may request: platforms whose presence is read from the status.
    A platform marked unverifiable is never requested, so its host is not allowed."""
    return frozenset(
        (urlsplit(entry.profile.replace("{handle}", "x")).hostname or "").lower()
        for entry in packs.platforms
        if entry.presence == "status"
    )


def scope_guard(scope, packs=None, *, resolve: Resolve | None = None) -> WebGuard:
    """A WebGuard for a scan: in-scope hosts (that resolve to public addresses) and the status-checkable platforms."""
    from scrutator.model import Entity, EntityType

    def in_scope(host: str) -> bool:
        try:
            return scope.decide_entity(Entity(type=EntityType.DOMAIN, value=host)).allowed
        except ValueError:
            return False

    return WebGuard(in_scope, profile_hosts(packs) if packs is not None else frozenset(), resolve=resolve)
