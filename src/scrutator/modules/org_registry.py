"""Package-registry and public-handle sources for the organisation phase (`scan --org`): brand protection.

- `packages` (keyless): does the organisation's brand name exist as a package or namespace on npm, PyPI, Docker Hub,
  crates.io, RubyGems and NuGet, and — where the registry exposes a homepage or repository URL — does that URL point
  back to an in-scope domain (a `confirmed namespace`)? Look-alikes of the brand name (from the existing variant
  generator, capped) that exist and are not linked to the organisation are recorded as well, and a brand name that is
  free on a registry is recorded for the dependency-confusion note. Author and maintainer fields are never stored.
- `handles` (keyless): does the organisation hold the brand handle on GitLab (public group), Docker Hub (namespace)
  and Bluesky (the seed domain as a handle, and `<brand>.bsky.social`)? Each is reported exists / absent / unverifiable
  by HTTP status or JSON, never guessed.
"""

import json
import re
from urllib.parse import quote, urlsplit

from scrutator.brand import lookalikes
from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules.base import Fact, Mode, Module, ModuleContext, http_failure
from scrutator.modules.registry import register
from scrutator.org import ORG_PHASE, POLITE_UA
from scrutator.org.state import get_state
from scrutator import __version__

PACKAGES_SOURCE = "packages"
HANDLES_SOURCE = "handles"
MAX_LOOKALIKES = 6  # look-alikes checked per typosquat-relevant registry
_PKG = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,62})$")


def _host(url: object) -> str:
    if not isinstance(url, str):
        return ""
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _linked(urls: list, roots) -> str | None:
    for url in urls:
        host = _host(url)
        if host and any(host == r or host.endswith("." + r) for r in roots):
            return host
    return None


@register
class PackageNamespaces(Module):
    """Brand name and look-alikes across the public package registries (see the module docstring)."""

    name = PACKAGES_SOURCE
    opt_in = "--org"
    accepts = frozenset({EntityType.DOMAIN})
    mode = Mode.PASSIVE
    phase = ORG_PHASE
    apex_only = True
    concurrency = 2
    timeout = 120.0
    rate_group = "packages"
    replayable = False  # a minimised projection is stored, not the registry's raw record (author fields are dropped)
    noncommercial = False
    licence_note = (
        "npm, PyPI, Docker Hub, crates.io, RubyGems and NuGet public read APIs (keyless, polite). Package existence "
        "and the homepage/repository URL only; author and maintainer fields are never stored."
    )

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Fact]:
        state = get_state(ctx)
        roots = set(state.roots) if state is not None else {entity.value}
        brand = entity.value.split(".")[0].lower()
        if not _PKG.match(brand):
            return [self._fact("PACKAGES brand", {"brand": brand, "checked": False, "reason": "the brand name is not a valid package name"})]
        out: list[Fact] = []
        for registry in _REGISTRIES:
            rec = await registry.check(brand, ctx, roots)
            out.append(self._fact(f"PACKAGE {registry.id} {brand}", {"registry": registry.id, "kind": registry.kind, "name": brand, "role": "brand", **rec}))
        seen = {brand}
        for registry in _TYPOSQUAT:
            count = 0
            for handle, how in lookalikes(brand):
                if count >= MAX_LOOKALIKES:
                    break
                if handle in seen or not _PKG.match(handle):
                    continue
                seen.add(handle)
                count += 1
                rec = await registry.check(handle, ctx, roots)
                out.append(self._fact(f"PACKAGE {registry.id} {handle}", {"registry": registry.id, "kind": registry.kind, "name": handle, "role": "lookalike", "how": how, **rec}))
        return out

    def _fact(self, request: str, payload: dict) -> Fact:
        return Fact(Evidence.create(PACKAGES_SOURCE, request, json.dumps(payload, sort_keys=True)))


class _Registry:
    def __init__(self, rid: str, kind: str, url, status, links=None):
        self.id, self.kind, self._url, self._status, self._links = rid, kind, url, status, links or (lambda d: [])

    async def check(self, name: str, ctx: ModuleContext, roots) -> dict:
        url = self._url(name)
        try:
            resp = await ctx.http.get(url, headers={"User-Agent": POLITE_UA + " brand-protection check"})
        except Exception as exc:  # noqa: BLE001
            return {"exists": None, "reason": f"no answer: {type(exc).__name__}"}
        state = self._status(resp.status_code)
        if state is None:
            return {"exists": None, "reason": f"HTTP {resp.status_code}: does not tell"}
        if not state:
            return {"exists": False}
        linked = None
        try:
            linked = _linked(self._links(resp.json()), roots)
        except ValueError:
            pass
        return {"exists": True, "linked_host": linked}


def _exists_404(status: int):
    if status == 200:
        return True
    if status == 404:
        return False
    return None


def _docker_status(status: int):
    # Docker Hub's /v2/users/{name}/ answers 200 for a user and 301/302/307/308 to /v2/orgs/ for an organisation; a name
    # that is neither answers 404. The /repositories endpoint cannot be used: it answers 200 with count 0 for any name.
    if status in (200, 301, 302, 307, 308):
        return True
    if status == 404:
        return False
    return None


# npm abbreviated metadata; homepage and repository.url link back
def _npm_links(d):
    urls = []
    if isinstance(d, dict):
        if isinstance(d.get("homepage"), str):
            urls.append(d["homepage"])
        repo = d.get("repository")
        if isinstance(repo, dict) and isinstance(repo.get("url"), str):
            urls.append(repo["url"])
    return urls


def _pypi_links(d):
    info = d.get("info", {}) if isinstance(d, dict) else {}
    urls = [info.get("home_page")]
    pu = info.get("project_urls") or {}
    if isinstance(pu, dict):
        urls.extend(v for v in pu.values() if isinstance(v, str))
    return [u for u in urls if isinstance(u, str)]


def _crates_links(d):
    c = d.get("crate", {}) if isinstance(d, dict) else {}
    return [u for u in (c.get("homepage"), c.get("repository"), c.get("documentation")) if isinstance(u, str)]


def _rubygems_links(d):
    if not isinstance(d, dict):
        return []
    return [u for u in (d.get("homepage_uri"), d.get("source_code_uri"), d.get("project_uri")) if isinstance(u, str)]


_REGISTRIES = [
    _Registry("npm", "package", lambda n: f"https://registry.npmjs.org/{quote(n, safe='')}", _exists_404, _npm_links),
    _Registry("pypi", "package", lambda n: f"https://pypi.org/pypi/{quote(n, safe='')}/json", _exists_404, _pypi_links),
    _Registry("dockerhub", "namespace", lambda n: f"https://hub.docker.com/v2/users/{quote(n, safe='')}/", _docker_status),
    _Registry("crates", "package", lambda n: f"https://crates.io/api/v1/crates/{quote(n, safe='')}", _exists_404, _crates_links),
    _Registry("rubygems", "package", lambda n: f"https://rubygems.org/api/v1/gems/{quote(n, safe='')}.json", _exists_404, _rubygems_links),
    _Registry("nuget", "package", lambda n: f"https://api.nuget.org/v3/registration5-semver1/{quote(n.lower(), safe='')}/index.json", _exists_404),
]
# the registries where a look-alike package is a dependency-confusion risk worth listing
_TYPOSQUAT = [r for r in _REGISTRIES if r.id in {"npm", "pypi", "dockerhub"}]


@register
class PublicHandles(Module):
    """The organisation's public handles on GitLab, Docker Hub and Bluesky (see the module docstring)."""

    name = HANDLES_SOURCE
    opt_in = "--org"
    accepts = frozenset({EntityType.DOMAIN})
    mode = Mode.PASSIVE
    phase = ORG_PHASE
    apex_only = True
    concurrency = 2
    timeout = 90.0
    rate_group = "handles"
    replayable = False
    noncommercial = False
    licence_note = (
        "GitLab (public group), Docker Hub (namespace) and Bluesky (handle resolution) public read APIs (keyless). "
        "Existence by HTTP status or JSON only; X, LinkedIn, Facebook, Instagram, TikTok, Reddit, Medium, Substack "
        "and Telegram are never requested (their terms restrict automated access, or the status does not tell)."
    )

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Fact]:
        brand = entity.value.split(".")[0].lower()
        out: list[Fact] = []
        out.append(await self._status(ctx, "gitlab", "group", brand, f"https://gitlab.com/api/v4/groups/{quote(brand, safe='')}?with_projects=false", _exists_404))
        out.append(await self._status(ctx, "dockerhub", "namespace", brand, f"https://hub.docker.com/v2/users/{quote(brand, safe='')}/", _docker_status))
        # Bluesky: the seed domain as a handle, and <brand>.bsky.social
        for handle in (entity.value, f"{brand}.bsky.social"):
            out.append(await self._bsky(ctx, handle))
        return out

    async def _status(self, ctx, platform, kind, handle, url, mapper) -> Fact:
        payload = {"platform": platform, "kind": kind, "handle": handle, "verified": True}
        try:
            resp = await ctx.http.get(url, headers={"User-Agent": POLITE_UA + " brand-protection check"})
            state = mapper(resp.status_code)
            payload["state"] = "exists" if state else ("absent" if state is False else "unverifiable")
            if state is None:
                payload["reason"] = f"HTTP {resp.status_code}: does not tell"
        except Exception as exc:  # noqa: BLE001
            payload["state"], payload["verified"] = "unverifiable", False
            payload["reason"] = f"no answer: {type(exc).__name__}"
        return Fact(Evidence.create(HANDLES_SOURCE, f"HANDLE {platform} {handle}", json.dumps(payload, sort_keys=True)))

    async def _bsky(self, ctx, handle) -> Fact:
        url = f"https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle={quote(handle, safe='')}"
        payload = {"platform": "bluesky", "kind": "handle", "handle": handle, "verified": True}
        try:
            resp = await ctx.http.get(url, headers={"User-Agent": POLITE_UA + " brand-protection check"})
            if resp.status_code == 200 and isinstance(resp.json().get("did"), str):
                payload["state"] = "exists"
            elif resp.status_code in (400, 404):
                payload["state"] = "absent"
            else:
                payload["state"], payload["reason"] = "unverifiable", f"HTTP {resp.status_code}"
        except Exception as exc:  # noqa: BLE001
            payload["state"], payload["verified"] = "unverifiable", False
            payload["reason"] = f"no answer: {type(exc).__name__}"
        return Fact(Evidence.create(HANDLES_SOURCE, f"HANDLE bluesky {handle}", json.dumps(payload, sort_keys=True)))
