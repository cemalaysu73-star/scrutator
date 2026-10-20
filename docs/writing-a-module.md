# Writing a module (a new data source)

A module is one file in `src/scrutator/modules/`. It asks one public service one question about one entity and
returns what the service said, as evidence. About thirty minutes for a service with a simple JSON API.

## What a module is allowed to be

- **Passive.** It asks a third-party service about the target; it never contacts the target. Active modules do not
  exist in v1.0.
- **Keyless, or keyed through the environment.** No accounts are created for users, and keys come only from an
  environment variable ([sources](sources.md#keyed-sources-optional-off-by-default)).
- **Within the service's terms.** No scraping of pages that offer no API, nothing that needs bypassing a limit. Note
  the terms in `licence_note`, and set `noncommercial = True` if the free tier is for non-commercial use.
- **Honest about failure.** A service that is down raises `SourceUnavailable`; an answer about one question that
  cannot be used raises `ModuleError`. Silence is never turned into "no names".

## The skeleton

```python
from scrutator.model import Entity, EntityType
from scrutator.modules._names import name_observations
from scrutator.modules.base import Module, ModuleContext, Observation, http_failure
from scrutator.modules.registry import register


@register
class AcmeNames(Module):
    """Hostnames Acme's passive DNS holds for a domain (no key)."""

    name = "acmenames"                      # the module name: used by --sources, `scrutator sources`, the audit log
    accepts = frozenset({EntityType.DOMAIN})
    apex_only = True                        # a service that lists every name under a domain is asked once per scan
    concurrency = 1
    timeout = 45.0
    licence_note = "Acme's free API: 100 calls per day; see acme.example/terms."

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation]:
        resp = await ctx.http.get("https://api.acme.example/v1/names", params={"domain": entity.value})
        if resp.status_code != 200:
            raise http_failure("acmenames", resp.status_code)      # 429 and 5xx mean "the source is struggling"
        lines = {row["host"]: str(row) for row in resp.json().get("names", []) if isinstance(row, dict) and "host" in row}
        return name_observations("acmenames", f"GET {resp.request.url}", entity.value, lines)
```

Rules the engine enforces for you, and ones you must keep:

- **Evidence is the raw answer, content-addressed.** `Evidence.create(source, request, payload)`; the `request` must be
  replayable (`GET <url>` with the full URL, or `DNS <type> <name>`). Store the slice of the answer that names the
  entity, so each finding cites only what it rests on.
- **Names you discover are claims.** Return them as `Observation`s. The engine decides their scope state and tier;
  a name outside the scope is recorded and never queried, whatever your module found.
- **Treat the answer as hostile.** It is attacker-influenced. Check types (`isinstance`), never `eval` or format it
  into a command, never follow a URL it contains (the egress guard would refuse it anyway), and keep the payload as
  data. Canonical entity values drop control characters, and the HTML/terminal output is escaped, but your parsing
  must not crash on a list where you expected an object.
- **Do not put secrets in a request.** For a keyed module set `needs_key = "SCRUTATOR_ACME_KEY"` and read the
  variable through `scrutator.keys` so that it is redacted from logs and errors.

## Register the host

Two lists decide where HTTP may go; both are short on purpose.

1. `src/scrutator/egress.py`: add `api.acme.example` to `SOURCE_HOSTS`. Only `https` on port 443 to a name on this list
   is sent; a redirect anywhere else is refused.
2. `src/scrutator/bundle/replay.py`: add it to `ALLOWED_HTTP_HOSTS` unless the module is keyed (a replay would need the
   key). Replay of a hostile bundle contacts only these hosts.

## Test it with a recorded response

Tests never touch the network. Use `respx` and the `make_ctx` fixture (see `tests/test_crtsh.py` and
`tests/test_hackertarget.py`):

```python
async def test_names_become_observations_with_evidence(make_ctx):
    with respx.mock() as router:
        router.get("https://api.acme.example/v1/names").mock(return_value=httpx.Response(200, json=RECORDED))
        obs = await AcmeNames().run(Entity(type=EntityType.DOMAIN, value="example.com"), make_ctx())
    assert {o.entity.value for o in obs} == {"www.example.com", "api.example.com"}
    assert all(o.evidence.source == "acmenames" and "api.acme.example" in o.evidence.request for o in obs)
```

Also test: a 503 and a 429 (`SourceUnavailable`), an invalid body, a hostile body (a list where an object is expected,
a name that is `<script>`, a 2 MB field, control characters), and, if the service reports a used-up quota in a
200 answer, that case. `tests/test_hostile_data.py` already runs **every registered module** through thirty hostile
bodies (wrong types, a 50,000-deep nesting, a 2 MB field, markup, control and bidirectional characters, look-alike
names, invalid UTF-8) and then builds the report, JSON, SARIF and HTML: yours is covered the moment it is registered,
and the checks are that nothing raises, entities are canonical and free of control characters, and the HTML stays inert.

## Document it

Add a row for the module to the table in [sources](sources.md) (a test fails if the table and
`scrutator sources` disagree), with what it gives and its terms in short, and a line in the CHANGELOG.

## Checklist

- [ ] one file in `modules/`, `@register`ed, passive, with `licence_note`
- [ ] host in `egress.SOURCE_HOSTS` (and `replay.ALLOWED_HTTP_HOSTS` if keyless)
- [ ] contract test on a recorded response, failure cases, a hostile case
- [ ] row in `docs/sources.md`; `python -m pytest` and `scrutator bench` pass
