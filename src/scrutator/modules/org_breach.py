"""Breach-history source for the organisation phase (`scan --org`): Have I Been Pwned's public breaches-by-domain
metadata endpoint.

It asks what *services under the organisation's domain* have been named in a public breach: the breach name, date,
record count and the kinds of data involved. It never asks, keeps or reports account lists or e-mail addresses: the
`breacheddomain` endpoint (which does) needs a key and proof of control of the domain and is never called. The answer
is metadata about the breached service, which HIBP publishes under CC BY 4.0; the report and the Organisation section
attribute it to haveibeenpwned.com.
"""

import json
from urllib.parse import quote

from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules.base import Fact, Mode, Module, ModuleContext, http_failure
from scrutator.modules.registry import register
from scrutator.org import ORG_PHASE, POLITE_UA
from scrutator import __version__

HIBP_SOURCE = "hibp"


@register
class HibpBreaches(Module):
    """Breaches a public index names for the organisation's domain (metadata only; see the module docstring)."""

    name = HIBP_SOURCE
    opt_in = "--org"
    accepts = frozenset({EntityType.DOMAIN})
    mode = Mode.PASSIVE
    phase = ORG_PHASE
    apex_only = True
    concurrency = 1
    timeout = 60.0
    rate_group = "hibp"
    noncommercial = False
    licence_note = (
        "Have I Been Pwned public breaches-by-domain metadata (keyless): the breached service's name, date, record "
        "count and data classes only; never account lists or addresses. Data is CC BY 4.0 — credit haveibeenpwned.com."
    )

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Fact]:
        url = f"https://haveibeenpwned.com/api/v3/breaches?domain={quote(entity.value, safe='')}"
        resp = await ctx.http.get(url, headers={"User-Agent": POLITE_UA, "Accept": "application/json"})
        if resp.status_code == 404:
            return [Fact(Evidence.create(HIBP_SOURCE, f"GET {url}", "[]"))]
        if resp.status_code != 200:
            raise http_failure(HIBP_SOURCE, resp.status_code)
        try:
            data = resp.json()
        except ValueError as exc:
            raise http_failure(HIBP_SOURCE, 502) from exc
        if not isinstance(data, list):
            raise http_failure(HIBP_SOURCE, 502)
        # the raw array is stored (it holds only breach metadata, no accounts), so a replay can re-compare it
        return [Fact(Evidence.create(HIBP_SOURCE, f"GET {url}", json.dumps(data, sort_keys=True)))]
