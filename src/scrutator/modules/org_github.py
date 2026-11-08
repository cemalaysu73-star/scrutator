"""GitHub organisation sources for the organisation phase (`scan --org`).

Two modules, both about the organisation's own GitHub *account and repositories*, never about people:

- `github_org` (keyless; the optional `SCRUTATOR_GITHUB_TOKEN` only raises the rate limit and is never logged): the
  public organisation account resolved from `--github-org` or from the GitHub username Wikidata records for the
  organisation, its public repositories (name, description, homepage, archived, fork, language, topics, last push,
  licence, default branch), and the *count* of public members (never their names). In-scope host names written in a
  repo's homepage, description or README become `claimed` candidate domains with the evidence that named them.
- `github_code_leaks` (`--code-leaks`, which needs `--org`, an authorisation and the token): a bounded look at the
  organisation's own public repositories for well-known credential FORMATS in likely files. It never stores the secret
  value: an exposure records only the format, repository, path, commit sha, a salted-hash fingerprint and a 2+2
  character mask.
"""

import hashlib
import json
import os
import re
import secrets
from urllib.parse import urlsplit

from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules._names import host_entity
from scrutator.modules.base import Fact, Mode, Module, ModuleContext, ModuleError, Observation, http_failure
from scrutator.modules.registry import register
from scrutator.org import ORG_PHASE, POLITE_UA
from scrutator.org.state import get_state
from scrutator.org.text import hosts_in, scrub, url_host, in_roots
from scrutator import __version__

GITHUB_SOURCE = "github"
LEAKS_SOURCE = "github_leaks"
TOKEN_VAR = "SCRUTATOR_GITHUB_TOKEN"
MAX_REPOS = 100  # one page, the most recently pushed
MAX_README = 5  # READMEs fetched for hostname extraction
README_BYTES = 8 * 1024
_HANDLE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")


def _headers() -> dict:
    headers = {"User-Agent": POLITE_UA, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get(TOKEN_VAR, "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"  # redacted everywhere by scrutator.keys
    return headers


def _last_page(link: str | None) -> int | None:
    if not link:
        return None
    for part in link.split(","):
        if 'rel="last"' in part:
            match = re.search(r"[?&]page=(\d+)", part)
            if match:
                return int(match.group(1))
    return None


def _org_login(state) -> str | None:
    if state is None:
        return None
    login = state.github_org_override or state.github_org
    if login and _HANDLE.match(login):
        return login
    return None


@register
class GithubOrg(Module):
    """The organisation's public GitHub account and repositories (see the module docstring)."""

    name = GITHUB_SOURCE
    opt_in = "--org"
    accepts = frozenset({EntityType.DOMAIN})
    mode = Mode.PASSIVE
    phase = ORG_PHASE
    apex_only = True
    concurrency = 1
    timeout = 90.0
    rate_group = "github"
    replayable = False  # the keyless rate limit is low, the listing churns, and a token may have been used
    optional_key = TOKEN_VAR
    noncommercial = False
    licence_note = (
        "GitHub REST API, keyless (60 requests/hour; the optional SCRUTATOR_GITHUB_TOKEN raises it and is never "
        "logged). The organisation account and its public repositories; the member COUNT only, never member names; "
        "no person fields."
    )

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation | Fact]:
        state = get_state(ctx)
        login = _org_login(state)
        if not login:
            return [Fact(Evidence.create(GITHUB_SOURCE, f"GITHUB org {entity.value}", json.dumps({"resolved": False, "reason": "no GitHub organisation resolved (set --github-org or it was not found in Wikidata)"}, sort_keys=True)))]
        roots = set(state.roots) if state is not None else {entity.value}
        out: list[Observation | Fact] = []
        headers = _headers()

        resp = await ctx.http.get(f"https://api.github.com/orgs/{login}", headers=headers)
        if resp.status_code == 404:
            out.append(self._fact(f"GITHUB org {login}", {"login": login, "found": False}))
            return out
        if resp.status_code != 200:
            raise http_failure(GITHUB_SOURCE, resp.status_code)
        org = resp.json()
        account = {
            "login": org.get("login"),
            "display_name": scrub(org.get("name"), 120),  # an organisation's display name, not a person's
            "description": scrub(org.get("description")),
            "blog": org.get("blog") if isinstance(org.get("blog"), str) else None,
            "is_verified": bool(org.get("is_verified")),
            "public_repos": org.get("public_repos"),
            "created_at": org.get("created_at"),
            "html_url": org.get("html_url"),
        }
        account_fact = self._fact(f"GITHUB org {login}", {"found": True, **account})
        out.append(account_fact)
        blog_host = url_host(account["blog"])
        for host in sorted(set(hosts_in(account["description"], roots)) | ({blog_host} if in_roots(blog_host, roots) else set())):
            target = host_entity(host)
            if target is not None and target.value != entity.value:
                out.append(Observation(target, "github_org_names_host", account_fact.evidence))

        members = await ctx.http.get(f"https://api.github.com/orgs/{login}/public_members", headers=headers, params={"per_page": "1"})
        if members.status_code == 200:
            count = _last_page(members.headers.get("link")) if members.headers.get("link") else (1 if members.json() else 0)
            out.append(self._fact(f"GITHUB members {login}", {"login": login, "public_members": count}))

        repos_resp = await ctx.http.get(
            f"https://api.github.com/orgs/{login}/repos", headers=headers,
            params={"type": "public", "sort": "pushed", "per_page": str(MAX_REPOS)},
        )
        if repos_resp.status_code != 200:
            raise http_failure(GITHUB_SOURCE, repos_resp.status_code)
        repos = repos_resp.json() if isinstance(repos_resp.json(), list) else []
        projected = []
        for repo in repos[:MAX_REPOS]:
            if not isinstance(repo, dict):
                continue
            rec = {
                "name": repo.get("name"),
                "full_name": repo.get("full_name"),
                "description": scrub(repo.get("description")),
                "homepage": repo.get("homepage") if isinstance(repo.get("homepage"), str) else None,
                "archived": bool(repo.get("archived")),
                "fork": bool(repo.get("fork")),
                "language": repo.get("language"),
                "topics": sorted(t for t in (repo.get("topics") or []) if isinstance(t, str))[:20],
                "pushed_at": repo.get("pushed_at"),
                "license": (repo.get("license") or {}).get("spdx_id") if isinstance(repo.get("license"), dict) else None,
                "default_branch": repo.get("default_branch"),
            }
            projected.append(rec)

        # in-scope hosts named in a repo's homepage, description or README become claimed candidate domains. The host
        # -> repo map is kept in the repos fact itself (so the section re-derives it with no clock and no cross-record
        # matching), and whether the naming repo is archived marks the host as named by an abandoned repo.
        named: dict[str, str] = {}
        archived_hosts: set[str] = set()
        for rec in projected:
            hosts = set(hosts_in(rec["description"], roots))
            hp = url_host(rec["homepage"])
            if in_roots(hp, roots):
                hosts.add(hp)
            if rec.get("full_name") and projected.index(rec) < MAX_README:
                readme = await ctx.http.get(f"https://api.github.com/repos/{rec['full_name']}/readme", headers={**headers, "Accept": "application/vnd.github.raw+json"})
                if readme.status_code == 200:
                    hosts |= set(hosts_in(scrub(readme.text[:README_BYTES], README_BYTES), roots))
            for host in hosts:
                named.setdefault(host, rec["name"])
                if rec["archived"]:
                    archived_hosts.add(host)
        named_hosts = sorted(h for h in named if h != entity.value)
        repos_fact = self._fact(f"GITHUB repos {login}", {
            "login": login, "count": len(projected), "repos": projected,
            "named_in_scope_hosts": named_hosts,
            "abandoned_named_hosts": sorted(h for h in archived_hosts if h != entity.value),
        })
        out.append(repos_fact)
        for host in named_hosts:
            target = host_entity(host)
            if target is not None:
                out.append(Observation(target, "github_repo_names_host", repos_fact.evidence))
        return out

    def _fact(self, request: str, payload: dict) -> Fact:
        return Fact(Evidence.create(GITHUB_SOURCE, request, json.dumps(payload, sort_keys=True)))


# ---------------------------------------------------------------------------------------------- code leaks (opt-in)

MAX_LEAK_REPOS = 10
MAX_TREE_FILES = 30  # likely files inspected per repository
MAX_FILE_BYTES = 128 * 1024
_LIKELY = re.compile(r"(^|/)(\.env(\.[\w.-]+)?|.*\.pem|.*\.pfx|.*\.p12|id_rsa|id_dsa|id_ecdsa|.*\.key|credentials|\.npmrc|\.pypirc|.*\.tfvars|secrets?\.(ya?ml|json|txt|ini|cfg)|config\.(ya?ml|json))$", re.I)
# well-known credential FORMATS (never the value is stored; only that one matched)
_FORMATS = {
    "aws_access_key_id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "aws_secret_access_key": re.compile(r"aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+]{40})['\"]?"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "github_pat": re.compile(r"\b(ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{60,})\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    "private_key_block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    "stripe_secret_key": re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b"),
    "slack_webhook": re.compile(r"hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"),
}


@register
class GithubCodeLeaks(Module):
    """`--code-leaks`: a bounded look at the organisation's own public repositories for credential FORMATS, storing a
    fingerprint and a mask, never the value (see the module docstring and docs/organisation.md)."""

    name = LEAKS_SOURCE
    source = GITHUB_SOURCE
    opt_in = "--code-leaks"
    accepts = frozenset({EntityType.DOMAIN})
    mode = Mode.PASSIVE
    phase = ORG_PHASE
    apex_only = True
    concurrency = 1
    timeout = 180.0
    rate_group = "github"
    replayable = False
    needs_key = TOKEN_VAR
    noncommercial = False
    licence_note = (
        "`--code-leaks`: the organisation's own public repositories only, capped, with the token. The secret value is "
        "never stored: an exposure records the format, repository, path, commit sha, a salted-hash fingerprint and a "
        "2+2 character mask. Rotate, then remove from history (responsible disclosure)."
    )

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Fact]:
        state = get_state(ctx)
        if state is None or not state.code_leaks:
            return []
        login = _org_login(state)
        if not login:
            raise ModuleError("code-leaks needs a resolved GitHub organisation (--github-org)")
        salt = state.leak_salt
        headers = _headers()
        out: list[Fact] = []
        repos_resp = await ctx.http.get(
            f"https://api.github.com/orgs/{login}/repos", headers=headers,
            params={"type": "public", "sort": "pushed", "per_page": str(MAX_LEAK_REPOS)},
        )
        if repos_resp.status_code != 200:
            raise http_failure(LEAKS_SOURCE, repos_resp.status_code)
        repos = [r for r in (repos_resp.json() or []) if isinstance(r, dict) and not r.get("fork")][:MAX_LEAK_REPOS]
        for repo in repos:
            full = repo.get("full_name")
            branch = repo.get("default_branch") or "main"
            if not full:
                continue
            await self._scan_repo(full, branch, ctx, headers, salt, out)
        out.append(Fact(Evidence.create(LEAKS_SOURCE, f"GITHUB code-leaks {login}", json.dumps({"login": login, "repositories_scanned": len(repos), "findings": sum(1 for f in out if f.evidence.request.startswith('GITHUB code-leak '))}, sort_keys=True))))
        return out

    async def _scan_repo(self, full: str, branch: str, ctx, headers, salt, out) -> None:
        tree = await ctx.http.get(f"https://api.github.com/repos/{full}/git/trees/{branch}", headers=headers, params={"recursive": "1"})
        if tree.status_code != 200:
            return
        entries = tree.json().get("tree") or []
        paths = [e.get("path") for e in entries if isinstance(e, dict) and e.get("type") == "blob" and isinstance(e.get("path"), str) and _LIKELY.search(e["path"])]
        for path in paths[:MAX_TREE_FILES]:
            blob = await ctx.http.get(f"https://api.github.com/repos/{full}/contents/{path}", headers={**headers, "Accept": "application/vnd.github.raw+json"}, params={"ref": branch})
            if blob.status_code != 200:
                continue
            text = blob.text[:MAX_FILE_BYTES]
            sha = blob.headers.get("x-github-content-sha") or ""
            for fmt, pattern in _FORMATS.items():
                match = pattern.search(text)
                if not match:
                    continue
                value = match.group(1) if match.groups() else match.group(0)
                out.append(Fact(Evidence.create(
                    LEAKS_SOURCE, f"GITHUB code-leak {full} {path} {fmt}",
                    json.dumps({
                        "repository": full, "path": path, "format": fmt, "commit_sha": sha,
                        "fingerprint": hashlib.sha256(salt + value.encode("utf-8", "replace")).hexdigest()[:16],
                        "mask": (value[:2] + "…" + value[-2:]) if len(value) >= 6 else "…",
                    }, sort_keys=True),
                )))
                break  # one record per file is enough to say "rotate and remove"
