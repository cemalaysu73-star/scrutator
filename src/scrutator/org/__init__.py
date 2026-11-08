"""Organisation-scoped sources (`scan --org`, off by default).

A passive scan maps a domain. These sources widen the lens to the *organisation* behind the domain: the legal entity
and its group (GLEIF, Wikidata), the breach history of its own services (Have I Been Pwned), the code it hosts in the
open (GitHub), the package namespaces that carry its brand (npm, PyPI, Docker Hub, crates.io, RubyGems, NuGet) and the
public handles it could own (GitLab, Docker Hub, Bluesky). They run only when the user asks for them, only about
organisations (legal entities, domains, repositories and namespaces), and never about natural persons.

The hard boundaries are in docs/organisation.md and enforced in the modules: no lookup of a person by name, username,
e-mail or phone; no collection of officers, directors, shareholders, employees or commit authors; no X, LinkedIn,
Facebook, Instagram, TikTok, Reddit, Medium, Substack or Telegram requests; no login, no account, no exploitation.
"""

from scrutator import __version__

ORG_PHASE = "org"
# The User-Agent the organisation sources send: the product, its version and the public project page, no personal
# address (the Wikidata, HIBP and crates.io policies ask for a descriptive one). Kept here, outside the modules, because
# the project page is not a host any module requests.
POLITE_UA = f"scrutator/{__version__} (+https://github.com/cemalaysu73-star/scrutator)"
