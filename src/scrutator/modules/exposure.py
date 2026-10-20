"""The organisation-exposure modules (design D18). They run only through `scrutator exposure` with a valid engagement
file (`opt_in`), on the engagement's own domains, and store only minimised records (scrutator/orgexposure.py): role
mailboxes as they are, every other address as a shape and a one-run pseudonym. None is replayable: what they store is
not what the source answered.

- `exposure_site`: the organisation's site: robots.txt, `/.well-known/security.txt`, the home page and at most three
  contact, about, team, imprint or legal pages it links to on the same site, one request a second, robots.txt honoured.
- `exposure_dns`: the DMARC record's report addresses and the SOA record's contact mailbox.
- `exposure_rdap`: e-mail addresses in the domain's RDAP contacts (rdap.org).
- `exposure_repos`: commit author and committer addresses in up to five recently pushed public repositories of each
  GitHub organisation the engagement file names (api.github.com, unauthenticated, 6 requests per organisation).
"""

import json
import re
from urllib.parse import urlsplit

import httpx

from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules.base import Fact, Module, ModuleContext, ModuleError, http_failure
from scrutator.modules.registry import register
from scrutator.orgexposure import find_addresses
from scrutator.web import MAX_ROBOTS, Pacers, page_links, read_text, robots_allows

PACE = 1.0  # requests a second to any one host
MAX_PAGES = 3  # contact-like pages followed from the home page
MAX_REPOS = 5
_PAGE_WORDS = re.compile(r"contact|about|team|imprint|impressum|kontakt|legal|privacy|security|people|staff", re.I)
_OPT_IN = "`scrutator exposure` (an engagement file is required)"


def _run(ctx: ModuleContext):
    run = ctx.engagement
    if run is None:
        raise ModuleError("organisation exposure runs only through `scrutator exposure` with an engagement file")
    return run


def _fact(source: str, request: str, payload: dict) -> Fact:
    return Fact(Evidence.create(source, request, json.dumps(payload, sort_keys=True)))


class _Exposure(Module):
    accepts = frozenset({EntityType.DOMAIN})
    opt_in = _OPT_IN
    replayable = False
    concurrency = 1
    priority = 90
    breaker = False


@register
class ExposureSite(_Exposure):
    """The organisation's own pages (see the module docstring). Contacts the organisation's site."""

    name = "exposure_site"
    timeout = 180.0
    licence_note = "Reads robots.txt, security.txt and a few contact pages of the organisation's own site (robots.txt honoured); only minimised addresses are kept."

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Fact]:
        run, web = _run(ctx), ctx.web
        if web is None:
            raise ModuleError("exposure_site needs the web client")
        pacers = Pacers(PACE)
        out: list[Fact] = []
        robots: dict[str, tuple[int | None, str]] = {}
        host = entity.value

        async def allowed(url: str) -> bool:
            site = urlsplit(url).hostname or ""
            if site not in robots:
                robots_url = f"https://{site}/robots.txt"
                try:
                    await pacers.take(robots_url)
                    response = await web.get(robots_url)
                    status = response.status_code
                    text = await read_text(response, MAX_ROBOTS) if 200 <= status < 300 else ""
                except httpx.HTTPError:
                    status, text = None, ""
                robots[site] = (status, text)
                out.append(_fact(self.name, f"ROBOTS {robots_url}", {"status": status, "allows_all_read": robots_allows(status, text, f"https://{site}/")}))
            return robots_allows(*robots[site], url)

        async def read(url: str, label: str) -> str:
            if not await allowed(url):
                out.append(_fact(self.name, f"{label} {url}", {"status": None, "skipped": "robots.txt does not allow it"}))
                return ""
            try:
                await pacers.take(url)
                response = await web.get(url)
            except httpx.HTTPError as exc:
                out.append(_fact(self.name, f"{label} {url}", {"status": None, "error": type(exc).__name__}))
                return ""
            if response.status_code != 200 or response.has_redirect_location:
                out.append(_fact(self.name, f"{label} {url}", {"status": response.status_code}))
                return ""
            text = await read_text(response)
            reduced = run.minimiser.reduce(find_addresses(text), url)
            out.append(_fact(self.name, f"{label} {url}", {"status": 200, **reduced}))
            return text

        await read(f"https://{host}/.well-known/security.txt", "SECURITYTXT")
        home = f"https://{host}/"
        body = await read(home, "PAGE")
        followed = 0
        for link in page_links(body, home):
            parts = urlsplit(link)
            if followed >= MAX_PAGES or parts.scheme != "https" or parts.hostname != host or not _PAGE_WORDS.search(parts.path):
                continue
            url = f"https://{host}{parts.path}"
            if url == home:
                continue
            followed += 1
            await read(url, "PAGE")
        return out


@register
class ExposureDns(_Exposure):
    """DMARC report addresses and the SOA contact of an engagement domain (DNS only)."""

    name = "exposure_dns"
    timeout = 30.0
    licence_note = "Your own resolver: the DMARC record and the SOA record of the engagement's domains."

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Fact]:
        run = _run(ctx)
        out = []
        dmarc = await ctx.resolver.lookup(f"_dmarc.{entity.value}", "TXT")
        found = []
        third_party = set()
        for record in dmarc:
            text = str(record).replace('" "', "").strip('"')
            for match in re.finditer(r"\b(?:rua|ruf)\s*=\s*([^;]+)", text, re.I):
                for part in match.group(1).split(","):
                    address = part.strip().removeprefix("mailto:").split("!", 1)[0]
                    found.append(address)
                    domain = address.rpartition("@")[2].lower()
                    if domain and not run.engagement.covers(domain):
                        third_party.add(domain)
        out.append(_fact(self.name, f"DMARC _dmarc.{entity.value}", {**run.minimiser.reduce(found, f"DMARC _dmarc.{entity.value}"),
                                                                     "report_processors": sorted(third_party)}))
        soa = await ctx.resolver.lookup(entity.value, "SOA")
        contacts = []
        for record in soa:
            fields = str(record).split()
            if len(fields) >= 2:
                rname = fields[1].rstrip(".").replace("\\.", "\x00")
                local, _, domain = rname.partition(".")
                if domain:
                    contacts.append(f"{local.replace(chr(0), '.')}@{domain.replace(chr(0), '.')}")
        out.append(_fact(self.name, f"SOA {entity.value}", run.minimiser.reduce(contacts, f"SOA {entity.value}")))
        return out


@register
class ExposureRdap(_Exposure):
    """E-mail addresses in the RDAP contacts of an engagement domain."""

    name = "exposure_rdap"
    timeout = 60.0
    licence_note = "rdap.org, as for the rdap module; only minimised addresses are kept."

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Fact]:
        run = _run(ctx)
        response = await ctx.http.get(f"https://rdap.org/domain/{entity.value}")
        if response.status_code == 404:
            return [_fact(self.name, f"RDAP {entity.value}", {"status": 404, "addresses": [], "outside_engagement": 0})]
        if response.status_code != 200:
            raise http_failure("rdap", response.status_code)
        try:
            data = response.json()
        except ValueError as exc:
            raise ModuleError("rdap returned invalid JSON") from exc
        found: list[str] = []

        def walk(node, depth=0):
            if depth > 20 or len(found) > 200:
                return
            if isinstance(node, list):
                if len(node) == 4 and node[0] == "email" and isinstance(node[3], str):
                    found.append(node[3])
                for item in node:
                    walk(item, depth + 1)
            elif isinstance(node, dict):
                for value in node.values():
                    walk(value, depth + 1)

        walk(data.get("entities", []) if isinstance(data, dict) else [])
        return [_fact(self.name, f"RDAP {entity.value}", {"status": 200, **run.minimiser.reduce(found, f"RDAP {entity.value}")})]


@register
class ExposureRepos(_Exposure):
    """Commit addresses in the public repositories of the GitHub organisations the engagement file names."""

    name = "exposure_repos"
    timeout = 120.0
    licence_note = "api.github.com without a key (60 requests an hour per address); only organisations the engagement file names; only minimised addresses are kept."

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Fact]:
        run = _run(ctx)
        if entity.value != run.seed or not run.engagement.github_orgs:
            return []
        out = []
        headers = {"Accept": "application/vnd.github+json"}
        for org in run.engagement.github_orgs:
            response = await ctx.http.get(f"https://api.github.com/orgs/{org}/repos", params={"type": "public", "sort": "pushed", "per_page": str(MAX_REPOS)}, headers=headers)
            if response.status_code != 200:
                raise http_failure("github", response.status_code)
            repos = response.json()
            names = [r["name"] for r in repos if isinstance(r, dict) and isinstance(r.get("name"), str) and re.fullmatch(r"[A-Za-z0-9._-]{1,100}", r["name"])][:MAX_REPOS] if isinstance(repos, list) else []
            for name in names:
                url = f"https://api.github.com/repos/{org}/{name}/commits"
                commits = await ctx.http.get(url, params={"per_page": "30"}, headers=headers)
                if commits.status_code != 200:
                    out.append(_fact(self.name, f"REPO {url}", {"status": commits.status_code, "addresses": [], "outside_engagement": 0}))
                    continue
                rows = commits.json()
                found = []
                noreply = 0
                for row in rows if isinstance(rows, list) else []:
                    for who in ("author", "committer"):
                        email = ((row.get("commit") or {}).get(who) or {}).get("email") if isinstance(row, dict) else None
                        if isinstance(email, str):
                            if email.lower().endswith("users.noreply.github.com") or email.lower() == "noreply@github.com":
                                noreply += 1
                            else:
                                found.append(email)
                out.append(_fact(self.name, f"REPO {url}", {"status": 200, **run.minimiser.reduce(found, url), "noreply": noreply}))
        return out
