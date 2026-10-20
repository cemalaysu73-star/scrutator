import json

from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules._names import host_entity, rel_for
from scrutator.modules.base import Module, ModuleContext, ModuleError, Observation, http_failure
from scrutator.modules.registry import register

MAX_PAGES = 2  # unauthenticated use is rate limited (10 calls per window): two pages per scan at most
_ROW_FIELDS = ("id", "cert_sha256", "pubkey_sha256", "issuer", "not_before", "not_after", "revoked")


def _slice(row: dict) -> dict:
    """The part of an issuance that is evidence for a name: which certificate, who issued it, when,
    which key, and whether it was revoked. Not the certificate's whole name list: that is large and
    belongs to the other names, and a small slice is what replay can check."""
    return {key: row[key] for key in _ROW_FIELDS if key in row}


@register
class CertSpotter(Module):
    """Certificate Transparency names via SSLMate's CertSpotter (no key). A second, independent view of
    the same logs crt.sh reads: when crt.sh answers 502 this one still can, and a name both see is
    backed by two sources."""

    name = "certspotter"
    accepts = frozenset({EntityType.DOMAIN})
    concurrency = 1
    timeout = 60.0
    priority = 0
    apex_only = True
    rate_group = "certspotter"
    noncommercial = True  # the README's source terms: free for non-commercial (or evaluation) use only
    licence_note = (
        "CertSpotter's free, unauthenticated API is for personal or evaluation use; production use needs an "
        "SSLMate account. SSLMate may restrict the free tier at any time."
    )

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation]:
        params: list[tuple[str, str]] = [
            ("domain", entity.value),
            ("include_subdomains", "true"),
            ("expand", "dns_names"),
            ("expand", "issuer"),
        ]
        observations: list[Observation] = []
        for _ in range(MAX_PAGES):
            resp = await ctx.http.get("https://api.certspotter.com/v1/issuances", params=params)
            if resp.status_code != 200:
                raise http_failure("certspotter", resp.status_code)
            try:
                rows = resp.json()
            except ValueError as exc:
                raise ModuleError("certspotter returned invalid JSON") from exc
            if not isinstance(rows, list):
                raise ModuleError("certspotter returned an unexpected payload")
            rows = [row for row in rows if isinstance(row, dict)]

            by_name: dict[str, list[dict]] = {}
            for row in rows:
                names = row.get("dns_names")
                for raw in names if isinstance(names, list) else []:
                    name = str(raw).strip().lower().removeprefix("*.")
                    found = host_entity(name)
                    if found is None or found.value == entity.value:
                        continue
                    bucket = by_name.setdefault(found.value, [])
                    if _slice(row) not in bucket:
                        bucket.append(_slice(row))
            request = f"GET {resp.request.url}"
            observations.extend(
                Observation(
                    Entity(type=EntityType.DOMAIN, value=name),
                    rel_for(entity.value, name),
                    Evidence.create(self.name, request, json.dumps(slices, sort_keys=True)),
                )
                for name, slices in sorted(by_name.items())
            )

            more = 'rel="next"' in resp.headers.get("link", "")
            last_id = rows[-1].get("id") if rows else None
            if not (more and last_id):
                break
            params = [(k, v) for k, v in params if k != "after"] + [("after", str(last_id))]
        return observations
