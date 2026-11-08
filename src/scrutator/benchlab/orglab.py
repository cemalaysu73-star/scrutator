"""The organisation-sources lab (`scan --org`): a planted organisation served entirely from fakes, no network.

The seed is `example.com`. The planted truth:

- Wikidata knows an organisation item for example.com ("Example Foundation", LEI `529900T8BM49AURSDO55`, GitHub
  `example-org`), with a parent (`holding.example`) and a subsidiary (`labs.example`).
- GLEIF knows that LEI, its parent `EXAMPLE HOLDING INC.` and one child `EXAMPLE LABS LLC`.
- Have I Been Pwned lists one breach of `example.com`.
- GitHub knows the `example-org` account (7 public members, 3 repos), one archived repo whose homepage is the in-scope
  host `old.example.com`, and a repo whose description names `api.example.com`. One repo's `.env` holds a secret.
- npm has the `example` package linked back to example.com (a confirmed namespace) and a look-alike `examp1e`; PyPI has
  no `example` package (unregistered). GitLab has the `example` group; Docker Hub does not; Bluesky resolves
  `example.com` but not `example.bsky.social`.

The one planted secret value (`SECRET_VALUE`) must appear in NO output: a canary test proves it is absent from the
evidence, report, bundle, logs and MCP output.
"""

import json

import httpx

from scrutator.benchlab.fakes import Router

SEED = "example.com"
LEI = "529900T8BM49AURSDO55"
GITHUB_ORG = "example-org"
# A planted credential in AWS access-key-id format (AWS's own documentation dummy value); it must never reach any output.
# Assembled at run time so the repository's secret scanner does not see a credential-shaped literal in the source.
SECRET_VALUE = "AKIA" + "IOSFODNN7" + "EXAMPLE"

TRUTH = {
    "legal_name": "Example Foundation",
    "lei": LEI,
    "parent": "EXAMPLE HOLDING INC.",
    "subsidiary": "EXAMPLE LABS LLC",
    "official_domains": {"holding.example", "labs.example"},
    "breach": "ExampleBreach",
    "github_members": 7,
    "github_named_hosts": {"old.example.com", "api.example.com"},
    "confirmed_namespace": ("npm", "example"),
    "lookalike_package": ("npm", "3xample"),
    "unregistered": ("pypi", "example"),
    "handles_exist": {("gitlab", "example"), ("bluesky", "example.com")},
}


# the risk rules this lab plants (each must fire on the lab scan; tests/test_org_sources.py, tests/test_planted_lab.py)
ORG_RULES = frozenset({"breach-history", "exposed-credential", "lookalike-package-exists", "brand-namespace-unregistered"})


def _json(obj) -> httpx.Response:
    return httpx.Response(200, content=json.dumps(obj).encode(), headers={"content-type": "application/json"})


def _sparql(bindings) -> httpx.Response:
    return httpx.Response(200, content=json.dumps({"head": {"vars": []}, "results": {"bindings": bindings}}).encode(),
                          headers={"content-type": "application/sparql-results+json"})


def _wd_site(request: httpx.Request) -> httpx.Response:
    query = request.url.params.get("query", "")
    if "P856 ?seedsite" in query:
        return _sparql([
            {"item": {"value": "http://www.wikidata.org/entity/Q10001"}, "itemLabel": {"value": "Example Foundation"},
             "lei": {"value": LEI}, "countryLabel": {"value": "Testland"}, "github": {"value": GITHUB_ORG},
             "site": {"value": "https://example.com/"}},
        ])
    if "wdt:P749 ?other" in query:  # relations
        return _sparql([
            {"rel": {"value": "parent"}, "other": {"value": "http://www.wikidata.org/entity/Q10002"},
             "otherLabel": {"value": "Example Holding"}, "site": {"value": "https://holding.example/"}},
            {"rel": {"value": "subsidiary"}, "other": {"value": "http://www.wikidata.org/entity/Q10003"},
             "otherLabel": {"value": "Example Labs"}, "site": {"value": "https://labs.example/"}},
        ])
    return _sparql([])


def _gleif_record(lei: str, name: str, country: str) -> dict:
    return {"id": lei, "type": "lei-records", "attributes": {
        "lei": lei, "entity": {"legalName": {"name": name}, "status": "ACTIVE", "jurisdiction": country,
        "legalAddress": {"country": country, "city": "Capital"}, "registeredAs": "REG-" + lei[:6]},
        "registration": {"lastUpdateDate": "2026-01-01T00:00:00Z", "status": "ISSUED"}}}


def _gleif(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path.endswith("/lei-records") and request.url.params.get("filter[entity.legalName]"):
        return _json({"meta": {"pagination": {"total": 1}}, "data": [_gleif_record(LEI, TRUTH["legal_name"], "US")]})
    if path.endswith(f"/lei-records/{LEI}"):
        return _json({"data": _gleif_record(LEI, TRUTH["legal_name"], "US")})
    if path.endswith("/direct-parent") or path.endswith("/ultimate-parent"):
        return _json({"data": _gleif_record("984500HOLDING00PARENT", TRUTH["parent"], "US")})
    if path.endswith("/direct-children"):
        return _json({"meta": {"pagination": {"total": 1}}, "data": [_gleif_record("98450CHILD000000LABS1", TRUTH["subsidiary"], "US")]})
    return httpx.Response(404, content=b'{"errors":[]}', headers={"content-type": "application/json"})


_BREACHES = [{"Name": "ExampleBreach", "Title": "Example Breach", "Domain": "example.com", "BreachDate": "2021-03-01",
              "AddedDate": "2021-04-01T00:00:00Z", "PwnCount": 1337, "DataClasses": ["Email addresses", "Passwords"],
              "IsVerified": True, "IsSensitive": False}]

_REPOS = [
    {"name": "app", "full_name": f"{GITHUB_ORG}/app", "description": "Main app. See api.example.com for the API.",
     "homepage": "", "archived": False, "fork": False, "language": "Python", "topics": ["security"],
     "pushed_at": "2026-10-01T00:00:00Z", "license": {"spdx_id": "Apache-2.0"}, "default_branch": "main"},
    {"name": "legacy", "full_name": f"{GITHUB_ORG}/legacy", "description": "Old site.",
     "homepage": "https://old.example.com", "archived": True, "fork": False, "language": "PHP", "topics": [],
     "pushed_at": "2020-01-01T00:00:00Z", "license": None, "default_branch": "master"},
    {"name": "mirror", "full_name": f"{GITHUB_ORG}/mirror", "description": "A fork.", "homepage": "",
     "archived": False, "fork": True, "language": "Go", "topics": [], "pushed_at": "2026-09-01T00:00:00Z",
     "license": {"spdx_id": "MIT"}, "default_branch": "main"},
]


def _github(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == f"/orgs/{GITHUB_ORG}":
        return _json({"login": GITHUB_ORG, "name": "Example Foundation", "description": "Docs at api.example.com.",
                      "blog": "https://example.com", "is_verified": True, "public_repos": 3,
                      "created_at": "2015-01-01T00:00:00Z", "html_url": f"https://github.com/{GITHUB_ORG}",
                      "email": "nobody@example.com"})
    if path == f"/orgs/{GITHUB_ORG}/public_members":
        return httpx.Response(200, content=b"[{}]", headers={
            "content-type": "application/json",
            "link": f'<https://api.github.com/organizations/1/public_members?per_page=1&page=7>; rel="last"'})
    if path == f"/orgs/{GITHUB_ORG}/repos":
        return _json(_REPOS)
    if path.endswith("/readme"):
        return httpx.Response(200, content=b"See docs at api.example.com and old.example.com", headers={"content-type": "application/vnd.github.raw+json"})
    if "/git/trees/" in path:
        return _json({"tree": [{"path": "README.md", "type": "blob"}, {"path": "config/.env", "type": "blob"}]})
    if "/contents/" in path:
        return httpx.Response(200, content=f"AWS_ACCESS_KEY_ID={SECRET_VALUE}\n".encode(),
                              headers={"content-type": "application/vnd.github.raw+json", "x-github-content-sha": "deadbeefcafe"})
    return httpx.Response(404, content=b'{"message":"Not Found"}', headers={"content-type": "application/json"})


def router() -> Router:
    lab = Router()
    lab.add("query.wikidata.org", "/sparql", _wd_site)
    lab.add("api.gleif.org", "/api/v1/.*", _gleif, regex=True)
    lab.add("haveibeenpwned.com", "/api/v3/breaches", lambda r: _json(_BREACHES) if r.url.params.get("domain") == SEED else _json([]))
    lab.add("api.github.com", "/.*", _github, regex=True)

    # package registries
    def npm(r):
        name = r.url.path.strip("/")
        if name == "example":
            return _json({"name": "example", "homepage": "https://example.com", "repository": {"url": "git+https://github.com/example-org/example.git"}})
        if name == "3xample":
            return _json({"name": "3xample", "homepage": "https://evil.test"})
        return httpx.Response(404, content=b'{"error":"Not found"}', headers={"content-type": "application/json"})
    lab.add("registry.npmjs.org", "/.*", npm, regex=True)
    lab.add("pypi.org", "/pypi/.*/json", lambda r: httpx.Response(404, content=b'{"message":"Not Found"}', headers={"content-type": "application/json"}), regex=True)
    lab.add("crates.io", "/api/v1/crates/.*", lambda r: httpx.Response(404, content=b'{"errors":[]}', headers={"content-type": "application/json"}), regex=True)
    lab.add("rubygems.org", "/api/v1/gems/.*", lambda r: httpx.Response(404, content=b"not found"), regex=True)
    lab.add("api.nuget.org", "/.*", lambda r: httpx.Response(404, content=b"<Error/>", headers={"content-type": "application/xml"}), regex=True)
    lab.add("hub.docker.com", "/v2/users/.*", lambda r: httpx.Response(404, content=b'{"detail":"Not found"}', headers={"content-type": "application/json"}), regex=True)

    # handles
    lab.add("gitlab.com", "/api/v4/groups/.*", lambda r: _json({"id": 1, "name": "Example"}) if r.url.path.endswith("/groups/example") else httpx.Response(404, content=b'{"message":"404"}', headers={"content-type": "application/json"}), regex=True)
    lab.add("public.api.bsky.app", "/xrpc/com.atproto.identity.resolveHandle", lambda r: _json({"did": "did:plc:example"}) if r.url.params.get("handle") == SEED else httpx.Response(400, content=b'{"error":"Unable"}', headers={"content-type": "application/json"}))
    return lab
