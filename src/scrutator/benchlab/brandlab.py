"""The brand-presence lab: a planted home page and planted platform answers, no network.

example.com's home page links to five platform accounts and to some things that are not accounts. The platforms answer
the way the bundled `platforms` pack says each one does; a few look-alike handles of the brand exist (planted), and
GitLab answers every unknown handle with a redirect to its sign-in page, as it does in reality, so absence can never be
concluded there. Used by tests/test_brand.py and by the `brand` section of `scrutator bench`.

What the lab must produce (TRUTH_*), and what it must never do: ask a platform the site does not link to, ask a
platform whose page does not tell (X, LinkedIn), call an unverifiable answer "absent", or fetch a page robots.txt
forbids.
"""

import httpx

from scrutator.benchlab.fakes import Router

SITE = "example.com"
HOME = f"https://{SITE}/"

HOME_PAGE = """<!doctype html><html><head><title>Example \x1b[31m</title>
<link rel="me" href="https://mastodon.social/@example">
<script>document.write('<a href="https://github.com/injected">')</script></head>
<body>
<a href="https://github.com/example-org">GitHub</a>
<a href="https://twitter.com/example">X</a>
<a href="https://www.linkedin.com/company/example/">LinkedIn</a>
<a href="https://gitlab.com/example">GitLab</a>
<a href="https://github.com/features">a GitHub page, not an account</a>
<a href="https://evil.example.net/@example">not a platform</a>
<a href="/about">about</a>
<a href="javascript:alert(1)">x</a>
</body></html>"""

# platform answers: (platform host path) -> status; everything else on a status platform is 404, on GitLab 302
EXISTING = {
    "https://github.com/example-org": 200,
    "https://github.com/examp1e": 200,
    "https://github.com/exampleofficial": 200,
    "https://mastodon.social/@example_official": 200,
}

# what the lab must report
TRUTH_OFFICIAL = {
    ("github", "example-org"): "exists",
    ("mastodon-social", "example"): "absent",
    ("x", "example"): "unverifiable",
    ("linkedin", "example"): "unverifiable",
    ("gitlab", "example"): "unverifiable",
}
TRUTH_RISKS = {
    ("brand-handle-unregistered", "handle:mastodon-social/example", "medium"),
    ("brand-handle-unregistered", "handle:github/example", "low"),
    ("brand-lookalike-handle", "handle:github/examp1e", "low"),
    ("brand-lookalike-handle", "handle:github/exampleofficial", "low"),
    ("brand-lookalike-handle", "handle:mastodon-social/example_official", "low"),
}
ALLOWED_HOSTS = {SITE, "github.com", "mastodon.social", "gitlab.com"}  # the site, and the status platforms it links to
NEVER_HOSTS = {"x.com", "twitter.com", "www.linkedin.com", "linkedin.com", "huggingface.co", "codeberg.org", "hub.docker.com", "evil.example.net"}


ROBOTS = "User-agent: *\nDisallow: /private\n"


def router(*, robots: str | None = ROBOTS, home: httpx.Response | None = None) -> Router:
    """The lab's internet. `robots=None` answers robots.txt with 404; `home` replaces the home page answer."""
    lab = Router()
    lab.add(SITE, "/robots.txt", httpx.Response(404) if robots is None else httpx.Response(200, text=robots))
    lab.add(f"www.{SITE}", "/robots.txt", httpx.Response(404))
    lab.add(SITE, "/", home or httpx.Response(200, text=HOME_PAGE, headers={"content-type": "text/html; charset=utf-8"}))
    lab.add(f"www.{SITE}", "/", httpx.Response(200, text=HOME_PAGE, headers={"content-type": "text/html"}))

    def platform(request: httpx.Request) -> httpx.Response:
        if request.url.host == "gitlab.com":
            return httpx.Response(302, headers={"location": "https://gitlab.com/users/sign_in"})
        return httpx.Response(EXISTING.get(str(request.url), 404))

    for host in ("github.com", "mastodon.social", "gitlab.com", "huggingface.co", "codeberg.org", "hub.docker.com", "x.com",
                 "twitter.com", "www.linkedin.com"):
        lab.add(host, "/", platform, regex=True)
    return lab


async def public_resolve(host: str) -> list[str]:
    """Every lab host resolves to a documentation address that counts as public for the guard."""
    return ["93.184.215.14"]
