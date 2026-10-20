import asyncio
import json
from urllib.parse import urlsplit

import httpx

from scrutator.brand import SOURCE, plan, profile_url
from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules.base import Fact, Module, ModuleContext, ModuleError
from scrutator.modules.registry import register
from scrutator.web import MAX_ROBOTS, Pacers, get_following, page_links, read_text, robots_allows


PACE = 1.0  # requests a second to any one host (the site, each platform)


@register
class BrandPresence(Module):
    """Brand presence (`scan --brand`, off otherwise): the platform accounts the organisation links from its own home
    page, whether they exist, and whether look-alike handles of the brand name exist on those platforms.

    It contacts the organisation's website, which no other module does: robots.txt first (for the `scrutator` agent),
    then the home page if robots.txt allows it, one request a second, no login, at most three in-scope redirects. Only
    the links to known platforms are kept from the page. Then, for each platform the page links to whose public
    profile page tells existence by its HTTP status (knowledge pack `platforms`), it asks about the published handles,
    the brand name and up to 20 look-alikes of it, one request a second per platform, without following redirects and
    without reading the page. Platforms the site does not link to are never asked about. See scrutator/brand.py for
    what is concluded from the answers."""

    name = "brand"
    accepts = frozenset({EntityType.DOMAIN})
    opt_in = "--brand"
    apex_only = True
    concurrency = 1
    timeout = 300.0
    priority = 95
    breaker = False  # its failures are many small hosts', not one source's
    licence_note = (
        "Reads the organisation's own home page (robots.txt honoured) and the HTTP status of public profile pages on "
        "github.com, gitlab.com, mastodon.social, huggingface.co, codeberg.org and hub.docker.com; nothing from those "
        "pages is kept. Platforms whose terms forbid automated access are never requested."
    )

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Fact]:
        web, packs = ctx.web, ctx.packs
        if web is None or packs is None:
            raise ModuleError("brand presence needs the web client (`scan --brand`)")
        apex = entity.value
        brand = apex.split(".")[0]
        pacers = Pacers(PACE)
        out: list[Fact] = [self._fact(f"SITE {apex}", {"domain": apex, "brand": brand})]
        robots: dict[str, tuple[int | None, str]] = {}

        def inside(url: str) -> bool:
            host = (urlsplit(url).hostname or "").lower()
            return urlsplit(url).scheme == "https" and (host == apex or host.endswith("." + apex))

        async def robots_for(url: str) -> tuple[int | None, str]:
            host = urlsplit(url).hostname
            if host not in robots:
                robots_url = f"https://{host}/robots.txt"
                status, text, error = None, "", ""
                try:
                    response, _, stopped = await get_following(web, robots_url, pacers, inside)
                    if response is not None and not stopped:
                        status = response.status_code
                        # only a robots.txt that was served is kept; a 404 page says nothing and is not stored
                        text = await read_text(response, MAX_ROBOTS) if 200 <= status < 300 else ""
                    elif response is not None:
                        status, error = response.status_code, stopped
                except httpx.HTTPError as exc:
                    error = f"{type(exc).__name__}: {exc}"[:200]
                robots[host] = (status, text)
                out.append(self._fact(f"ROBOTS {robots_url}", {"status": status, "text": text, **({"error": error} if error else {})}))
            return robots[host]

        home = f"https://{apex}/"
        links: list[str] = []
        current, hops = home, []
        for _ in range(4):
            status, text = await robots_for(current)
            if not robots_allows(status, text, current):
                out.append(self._fact(f"PAGE {current}", {"status": None, "skipped": "robots.txt does not allow it", "hops": hops}))
                break
            try:
                await pacers.take(current)
                response = await web.get(current)
            except httpx.HTTPError as exc:
                out.append(self._fact(f"PAGE {current}", {"status": None, "error": f"{type(exc).__name__}: {exc}"[:200], "hops": hops}))
                break
            if response.has_redirect_location:
                target = str(response.url.join(response.headers["Location"]))
                if not inside(target) or len(hops) >= 3:
                    out.append(self._fact(f"PAGE {current}", {"status": response.status_code, "hops": hops,
                                                              "stopped": f"redirect to {urlsplit(target).hostname} not followed: outside the scope or too many hops"}))
                    break
                hops.append(current)
                current = target
                continue
            body = await read_text(response) if "html" in response.headers.get("content-type", "html") else ""
            links = [link for link in page_links(body, str(response.url)) if _platform_host(packs, link)]
            out.append(self._fact(f"PAGE {current}", {"status": response.status_code, "hops": hops, "links": links}))
            break

        official, checks = plan(packs, brand, links)
        entries = {e.id: e for e in packs.platforms}

        async def check_platform(platform_id: str, wanted: list[tuple[str, str, str]]) -> list[Fact]:
            facts = []
            for handle, _, _ in wanted:
                url = profile_url(entries[platform_id], handle)
                payload: dict
                try:
                    await pacers.take(url)
                    response = await web.get(url)
                    payload = {"status": response.status_code}
                    if response.has_redirect_location:
                        payload["location_host"] = (urlsplit(response.headers["Location"]).hostname or "")[:100]
                except httpx.HTTPError as exc:
                    payload = {"status": None, "error": type(exc).__name__}
                facts.append(self._fact(f"PROFILE {url}", payload))
            return facts

        for facts in await asyncio.gather(*(check_platform(p, w) for p, w in sorted(checks.items()))):
            out.extend(facts)
        return out

    def _fact(self, request: str, payload: dict) -> Fact:
        return Fact(Evidence.create(SOURCE, request, json.dumps(payload, sort_keys=True)))


def _platform_host(packs, url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    return any(host in entry.link_hosts for entry in packs.platforms)
