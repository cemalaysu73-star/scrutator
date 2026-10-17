import json

from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules._names import host_entity
from scrutator.modules.base import Module, ModuleContext, ModuleError, Observation, http_failure
from scrutator.modules.registry import register

MAX_ROWS = 200
MAX_ANSWERS = 30  # distinct historical answers kept: a CDN that rotates addresses is not 200 new entities
_ROW_FIELDS = ("query", "answer", "rrtype", "firstSeenTimestamp", "lastSeenTimestamp", "times")
_HOSTNAME_TYPES = {"cname": "historic_cname", "ns": "historic_ns", "mx": "historic_mx"}


@register
class Mnemonic(Module):
    """DNS history of a domain from mnemonic's passive DNS (`api.mnemonic.no/pdns/v3`, no key): which
    addresses, name servers, mail servers and aliases it has had, with first and last seen.

    The service answers for one exact name; it cannot list subdomains. Everything it adds is
    history, recorded under relations of its own (`historically_resolved_to`, `historic_ns`, ...): an
    address that used to be the domain's is not an address it has now, and it is never scanned (the
    engine records it as outside the scope)."""

    name = "mnemonic"
    accepts = frozenset({EntityType.DOMAIN})
    concurrency = 1
    timeout = 45.0
    priority = 5
    apex_only = True
    licence_note = (
        "mnemonic's public passive DNS carries TLP:white rows; its terms of use could not be retrieved, so "
        "treat it as best effort and check mnemonic.no before commercial use."
    )

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation]:
        resp = await ctx.http.get(
            f"https://api.mnemonic.no/pdns/v3/{entity.value}", params={"limit": str(MAX_ROWS)}
        )
        if resp.status_code != 200:
            raise http_failure("mnemonic", resp.status_code)
        try:
            data = resp.json()
        except ValueError as exc:
            raise ModuleError("mnemonic returned invalid JSON") from exc
        if not isinstance(data, dict) or data.get("responseCode") != 200 or not isinstance(data.get("data"), list):
            raise ModuleError("mnemonic returned an unexpected payload")

        grouped: dict[tuple[str, str], list[dict]] = {}
        for row in data["data"]:
            if not isinstance(row, dict) or not isinstance(row.get("answer"), str):
                continue
            rrtype = str(row.get("rrtype", "")).lower()
            answer = row["answer"].strip()
            if rrtype in ("a", "aaaa"):
                key = ("ip", answer)
            elif rrtype in _HOSTNAME_TYPES:
                key = (rrtype, answer.split()[-1].rstrip(".").lower() if answer.split() else "")
            else:
                continue
            grouped.setdefault(key, []).append({k: row[k] for k in _ROW_FIELDS if k in row})

        recent = sorted(
            grouped.items(), key=lambda kv: max(r.get("lastSeenTimestamp", 0) for r in kv[1]), reverse=True
        )
        request = f"GET {resp.request.url}"
        observations: list[Observation] = []
        for (kind, answer), rows in recent[:MAX_ANSWERS]:
            if kind == "ip":
                try:
                    target, rel = Entity(type=EntityType.IP, value=answer), "historically_resolved_to"
                except ValueError:
                    continue
            else:
                target, rel = host_entity(answer), _HOSTNAME_TYPES[kind]
                if target is None or target.value == entity.value:
                    continue
            observations.append(
                Observation(target, rel, Evidence.create(self.name, request, json.dumps(rows, sort_keys=True)))
            )
        return sorted(observations, key=lambda o: (o.rel, o.entity.value))
