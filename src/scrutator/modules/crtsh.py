import json
import re

from scrutator import pgwire

from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules._names import host_entity, rel_for
from scrutator.modules.base import Module, ModuleContext, ModuleError, Observation, SourceUnavailable, http_failure
from scrutator.modules.registry import register

_CERT_FIELDS = ("id", "issuer_name", "name_value", "not_before", "not_after")
_SAFE = re.compile(r"[a-z0-9_.-]+")
DB_HOST, DB_PORT = "crt.sh", 5432
DB_TIMEOUT = 25.0
DB_FALLBACK = True  # the test suite turns it off: no test may open a connection to crt.sh
_HTTP_ATTEMPTS = {"scrutator_attempts": 2}  # with the database behind it, a third try of a 502 is not worth its wait


def db_request(domain: str) -> str:
    """The evidence request of a database lookup: the fixed query below, about one domain (what `verify --replay`
    re-runs; it never runs SQL from a bundle)."""
    return f"PGSQL crt.sh:5432/certwatch identities {domain}"


def db_query(domain: str) -> str:
    """crt.sh's own search, as SQL: certificates whose identities include the domain or a name under it, with the
    fields the web search's JSON gives. `domain` is a canonical host name (checked by the caller)."""
    if not _SAFE.fullmatch(domain):
        raise ModuleError("refusing to build a query for a name that is not a plain host name")
    return (
        "WITH ci AS (SELECT min(sub.CERTIFICATE_ID) ID, min(sub.ISSUER_CA_ID) ISSUER_CA_ID, "
        "array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES, x509_notBefore(sub.CERTIFICATE) NOT_BEFORE, "
        "x509_notAfter(sub.CERTIFICATE) NOT_AFTER FROM (SELECT * FROM certificate_and_identities cai "
        f"WHERE plainto_tsquery('certwatch', '{domain}') @@ identities(cai.CERTIFICATE) "
        f"AND (lower(cai.NAME_VALUE) = '{domain}' OR lower(cai.NAME_VALUE) LIKE '%.{domain}') LIMIT 10000) sub "
        "GROUP BY sub.CERTIFICATE) SELECT ci.ID id, ca.NAME issuer_name, array_to_string(ci.NAME_VALUES, chr(10)) name_value, "
        "ci.NOT_BEFORE not_before, ci.NOT_AFTER not_after FROM ci JOIN ca ON ci.ISSUER_CA_ID = ca.ID ORDER BY ci.ID"
    )


def _iso(value: str | None) -> str | None:
    return value.replace(" ", "T", 1) if isinstance(value, str) else value


def db_rows(columns: list[str], rows: list[list]) -> list[dict]:
    """The database's answer in the shape of the web search's JSON rows."""
    out = []
    for row in rows:
        item = dict(zip(columns, row))
        try:
            item["id"] = int(item.get("id")) if item.get("id") is not None else None
        except ValueError:
            pass
        item["not_before"], item["not_after"] = _iso(item.get("not_before")), _iso(item.get("not_after"))
        out.append({key: item.get(key) for key in _CERT_FIELDS})
    return out


@register
class CrtSh(Module):
    """Certificate Transparency names via crt.sh (no key).

    The web search (`crt.sh/?output=json`) is asked first. When it fails (in every benchmark run since R4 it answered
    HTTP 502), the same data is read from crt.sh's public database (`pgwire`, the guest account crt.sh documents), with
    the query `db_query` and the same row shape, recorded as `PGSQL crt.sh:5432/certwatch identities <domain>`. The
    database is slower (20-30 s measured on 2026-10-21) and also refuses when it has too many clients, which is
    recorded like any failure."""

    name = "crtsh"
    name_weight = 3
    accepts = frozenset({EntityType.DOMAIN})
    concurrency = 1
    timeout = 90.0
    priority = 0
    apex_only = True

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation]:
        try:
            rows, request = await self._web(entity, ctx)
        except Exception as web_failure:  # noqa: BLE001 - the web front end failing is what the database is for
            if not DB_FALLBACK:
                raise
            try:
                columns, raw = await pgwire.query(DB_HOST, db_query(entity.value), port=DB_PORT, timeout=DB_TIMEOUT)
            except Exception as db_failure:  # noqa: BLE001
                raise SourceUnavailable(f"{web_failure}; its database did not answer either ({type(db_failure).__name__}: {db_failure})") from web_failure
            rows, request = db_rows(columns, raw), db_request(entity.value)
        return self._observations(entity, rows, request)

    async def _web(self, entity: Entity, ctx: ModuleContext) -> tuple[list, str]:
        resp = await ctx.http.get("https://crt.sh/", params={"q": f"%.{entity.value}", "output": "json"}, extensions=_HTTP_ATTEMPTS)
        if resp.status_code != 200:
            raise http_failure("crt.sh", resp.status_code)
        try:
            rows = resp.json()
        except ValueError as exc:
            raise ModuleError("crt.sh returned invalid JSON") from exc
        if not isinstance(rows, list):
            raise ModuleError("crt.sh returned an unexpected payload")
        return rows, f"GET {resp.request.url}"

    def _observations(self, entity: Entity, rows: list, request: str) -> list[Observation]:

        certs_by_name: dict[str, list[dict]] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            summary = {key: row.get(key) for key in _CERT_FIELDS}
            for raw in str(row.get("name_value", "")).splitlines():
                name = raw.strip().lower().removeprefix("*.")
                found = host_entity(name)
                if found is None or found.value == entity.value:
                    continue
                bucket = certs_by_name.setdefault(found.value, [])
                if summary not in bucket:
                    bucket.append(summary)

        return [
            Observation(
                Entity(type=EntityType.DOMAIN, value=name),
                rel_for(entity.value, name),
                Evidence.create(self.name, request, json.dumps(certs, sort_keys=True)),
            )
            for name, certs in sorted(certs_by_name.items())
        ]
