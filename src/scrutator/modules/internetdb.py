import json

from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules._names import host_entity
from scrutator.modules.base import Fact, Module, ModuleContext, ModuleError, Observation, http_failure
from scrutator.modules.registry import register

MAX_HOSTNAMES = 50  # an address shared by thousands of sites is not thousands of entities


def _ordered(values: list) -> list:
    """Numbers (ports) in numeric order, anything else as text."""
    return sorted(values) if all(isinstance(v, int) for v in values) else sorted(values, key=str)


@register
class InternetDb(Module):
    """What Shodan's InternetDB knows about an address (`internetdb.shodan.io`, no key): open ports,
    product names (CPE), vulnerabilities Shodan associates with them, and the host names it has seen.

    Passive: it is Shodan's own, earlier scan, nothing is sent to the address. The engine only runs
    this on addresses that are in scope or reached from an in-scope name (`linked`). Most addresses
    are simply not indexed (HTTP 404), which says nothing and records nothing.

    Each kind of fact is its own small evidence record ("ports", "cpes", "vulns"), so a replay can
    say which of them still holds. The data is as old as Shodan's last visit: a risk built from it
    is rated low confidence."""

    name = "internetdb"
    accepts = frozenset({EntityType.IP})
    concurrency = 4
    timeout = 30.0
    priority = 25
    rate_group = "internetdb"
    noncommercial = True  # the README's source terms: free for non-commercial (or evaluation) use only
    licence_note = (
        "Shodan InternetDB is free for non-commercial use only; a revenue-generating use needs a Shodan "
        "enterprise licence. Bundles that embed its data inherit this."
    )

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation | Fact]:
        resp = await ctx.http.get(f"https://internetdb.shodan.io/{entity.value}")
        if resp.status_code == 404:
            return []
        if resp.status_code != 200:
            raise http_failure("internetdb", resp.status_code)
        try:
            data = resp.json()
        except ValueError as exc:
            raise ModuleError("internetdb returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise ModuleError("internetdb returned an unexpected payload")

        request = f"GET {resp.request.url}"

        def record(key: str, values: list) -> Evidence:
            return Evidence.create(self.name, request, json.dumps([{"ip": entity.value, key: values}], sort_keys=True))

        out: list[Observation | Fact] = []
        for key in ("ports", "cpes", "vulns"):
            values = data.get(key)
            if isinstance(values, list) and values:
                out.append(Fact(record(key, _ordered(values))))
        names = data.get("hostnames")
        for raw in sorted({str(h).strip().lower() for h in names if isinstance(h, str)})[:MAX_HOSTNAMES] if isinstance(names, list) else []:
            target = host_entity(raw)
            if target is not None:
                out.append(Observation(target, "known_as", record("hostnames", [target.value])))
        return out
