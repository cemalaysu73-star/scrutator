"""Company-record sources for the organisation phase (`scan --org`): Wikidata and GLEIF.

Both answer about legal entities and organisations only, never natural persons. They widen attribution with the
organisation's *other* official domains (a parent's or a subsidiary's site) as candidate scope entries, and they fill
the report's Organisation section (legal entities, parents, subsidiaries, official domains) with evidence to drill into.

- `wikidata` (keyless): the organisation item whose official website (P856) is the seed, filtered in the query to an
  instance of a subclass of organisation (Q43229) so a software or a product item is never taken as the organisation.
  Its label is a legal-name candidate; its LEI (P1278) is handed to `gleif`; its, its parent's (P749) and its
  subsidiaries' (P355) official websites become candidate domains. Query service policy: a 60 s query limit and a
  descriptive User-Agent (sent, with no personal address). Data is CC0.
- `gleif` (keyless): the LEI record for a known LEI or an exact legal name (no fuzzy match), then the direct and
  ultimate parent and the direct children, as organisations. Data is CC0.
"""

import json
from urllib.parse import quote, urlsplit

from scrutator.model import Entity, EntityType, Evidence
from scrutator.modules._names import host_entity, usable_org
from scrutator.modules.base import Fact, Mode, Module, ModuleContext, Observation, http_failure
from scrutator.modules.registry import register
from scrutator.org import ORG_PHASE, POLITE_UA
from scrutator.org.state import get_state
from scrutator import __version__

WIKIDATA_SOURCE = "wikidata"
GLEIF_SOURCE = "gleif"
ORG_CLASS = "Q43229"  # organization
MAX_CHILDREN = 25
MAX_SITES = 25


def _site_variants(domain: str) -> list[str]:
    forms = []
    for host in (domain, f"www.{domain}"):
        for scheme in ("https", "http"):
            forms.append(f"{scheme}://{host}/")
            forms.append(f"{scheme}://{host}")
    return forms


def _sparql_url(query: str) -> str:
    return "https://query.wikidata.org/sparql?format=json&query=" + quote(query, safe="")


def _domain_of(url: object) -> str | None:
    if not isinstance(url, str):
        return None
    try:
        host = (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    return host or None


def _qid(uri: str) -> str:
    return uri.rsplit("/", 1)[-1]


@register
class WikidataOrg(Module):
    """The organisation behind the seed, from Wikidata's official-website property (see the module docstring)."""

    name = WIKIDATA_SOURCE
    opt_in = "--org"
    accepts = frozenset({EntityType.DOMAIN})
    mode = Mode.PASSIVE
    phase = ORG_PHASE
    apex_only = True
    concurrency = 1
    timeout = 90.0
    rate_group = "wikidata"
    noncommercial = False
    licence_note = (
        "Wikidata Query Service: a 60 s query limit and a descriptive User-Agent; data is CC0. Only organisation items "
        "(instances of a subclass of organization) are read; a human item is never followed."
    )

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation | Fact]:
        state = get_state(ctx)
        out: list[Observation | Fact] = []
        headers = {"User-Agent": POLITE_UA, "Accept": "application/sparql-results+json"}
        items = await self._resolve(entity.value, ctx, headers, out, state)
        if not items and state is not None and state.known_names():
            items = await self._by_label(state.known_names()[0], ctx, headers, out, state)
        for qid in sorted(items):
            await self._relations(qid, entity.value, ctx, headers, out, state)
        return out

    async def _query(self, query: str, ctx: ModuleContext, headers: dict) -> list[dict]:
        url = _sparql_url(query)
        resp = await ctx.http.get(url, headers=headers)
        if resp.status_code != 200:
            raise http_failure(WIKIDATA_SOURCE, resp.status_code)
        try:
            return resp.json().get("results", {}).get("bindings", [])
        except ValueError as exc:
            raise http_failure(WIKIDATA_SOURCE, 502) from exc

    def _fact(self, request: str, payload: dict) -> Fact:
        return Fact(Evidence.create(WIKIDATA_SOURCE, request, json.dumps(payload, sort_keys=True)))

    async def _resolve(self, domain: str, ctx, headers, out, state) -> set[str]:
        values = " ".join(f"<{v}>" for v in _site_variants(domain))
        query = (
            "SELECT ?item ?itemLabel ?lei ?countryLabel ?ticker ?github ?site WHERE { "
            f"VALUES ?seedsite {{ {values} }} ?item wdt:P856 ?seedsite . "
            f"?item wdt:P31/wdt:P279* wd:{ORG_CLASS} . "
            "OPTIONAL { ?item wdt:P1278 ?lei. } OPTIONAL { ?item wdt:P17 ?country. } "
            "OPTIONAL { ?item wdt:P249 ?ticker. } OPTIONAL { ?item wdt:P2037 ?github. } OPTIONAL { ?item wdt:P856 ?site. } "
            'SERVICE wikibase:label { bd:serviceParam wikibase:language "en". } } LIMIT 100'
        )
        bindings = await self._query(query, ctx, headers)
        return self._collect(bindings, f"WIKIDATA site {domain}", out, state)

    async def _by_label(self, name: str, ctx, headers, out, state) -> set[str]:
        safe = name.replace("\\", "\\\\").replace('"', '\\"')
        query = (
            "SELECT ?item ?itemLabel ?lei ?countryLabel ?ticker ?site WHERE { "
            f'?item rdfs:label "{safe}"@en . ?item wdt:P31/wdt:P279* wd:{ORG_CLASS} . '
            "OPTIONAL { ?item wdt:P1278 ?lei. } OPTIONAL { ?item wdt:P17 ?country. } "
            "OPTIONAL { ?item wdt:P249 ?ticker. } OPTIONAL { ?item wdt:P856 ?site. } "
            'SERVICE wikibase:label { bd:serviceParam wikibase:language "en". } } LIMIT 100'
        )
        bindings = await self._query(query, ctx, headers)
        return self._collect(bindings, f"WIKIDATA label {name}", out, state)

    def _collect(self, bindings: list[dict], request: str, out, state) -> set[str]:
        items: dict[str, dict] = {}
        for row in bindings:
            item = row.get("item", {}).get("value")
            if not item:
                continue
            qid = _qid(item)
            rec = items.setdefault(qid, {"qid": qid, "label": None, "lei": None, "country": None, "ticker": None, "github": None, "sites": set()})
            if rec["label"] is None:
                label = row.get("itemLabel", {}).get("value")
                rec["label"] = label if label and label != qid else None
            for key, col in (("lei", "lei"), ("country", "countryLabel"), ("ticker", "ticker"), ("github", "github")):
                if rec[key] is None and row.get(col, {}).get("value"):
                    rec[key] = row[col]["value"]
            site = _domain_of(row.get("site", {}).get("value"))
            if site:
                rec["sites"].add(site)
        payload = {"items": [{**{k: v for k, v in rec.items() if k != "sites"}, "sites": sorted(rec["sites"])} for rec in items.values()]}
        fact = self._fact(request, payload)
        out.append(fact)
        roots = set(state.roots) if state is not None else set()
        for rec in items.values():
            if state is not None:
                state.add_name(rec["label"], f"Wikidata {rec['qid']}", (fact.evidence.id,))
                if rec["lei"] and not state.lei:
                    state.lei = rec["lei"]
                if rec["github"] and not state.github_org and not state.github_org_override:
                    gh = str(rec["github"]).strip().strip("/")
                    if gh and "/" not in gh:
                        state.github_org = gh
            # the organisation's own other official websites (out of scope) become candidate domains too
            for site in sorted(rec["sites"]):
                if any(site == r or site.endswith("." + r) for r in roots):
                    continue
                target = host_entity(site)
                if target is not None:
                    out.append(Observation(target, "org_official_site", fact.evidence))
        return set(items)

    async def _relations(self, qid: str, seed: str, ctx, headers, out, state) -> None:
        query = (
            "SELECT ?rel ?other ?otherLabel ?site WHERE { "
            f"{{ wd:{qid} wdt:P749 ?other. BIND('parent' AS ?rel) }} UNION "
            f"{{ wd:{qid} wdt:P355 ?other. BIND('subsidiary' AS ?rel) }} "
            "OPTIONAL { ?other wdt:P856 ?site. } "
            'SERVICE wikibase:label { bd:serviceParam wikibase:language "en". } } LIMIT 200'
        )
        bindings = await self._query(query, ctx, headers)
        rels: dict[str, dict] = {}
        for row in bindings:
            other = row.get("other", {}).get("value")
            if not other:
                continue
            other_qid = _qid(other)
            rel = row.get("rel", {}).get("value", "")
            rec = rels.setdefault(other_qid, {"qid": other_qid, "rel": rel, "label": None, "sites": set()})
            if rec["label"] is None:
                label = row.get("otherLabel", {}).get("value")
                rec["label"] = label if label and label != other_qid else None
            site = _domain_of(row.get("site", {}).get("value"))
            if site:
                rec["sites"].add(site)
        payload = {"qid": qid, "relations": [{**{k: v for k, v in r.items() if k != "sites"}, "sites": sorted(r["sites"])[:MAX_SITES]} for r in rels.values()]}
        out.append(self._fact(f"WIKIDATA relations {qid}", payload))
        evidence_id = out[-1].evidence.id
        # the parent's and the subsidiaries' official websites become candidate domains for attribution (org_record)
        for rec in rels.values():
            for site in sorted(rec["sites"])[:MAX_SITES]:
                target = host_entity(site)
                if target is not None and target.value != seed:
                    out.append(Observation(target, "org_official_site", Evidence.create(WIKIDATA_SOURCE, f"WIKIDATA relations {qid}", json.dumps(payload, sort_keys=True))))


@register
class GleifCompany(Module):
    """The legal entity, its parents and its children from GLEIF's LEI records (see the module docstring)."""

    name = GLEIF_SOURCE
    opt_in = "--org"
    accepts = frozenset({EntityType.DOMAIN})
    mode = Mode.PASSIVE
    phase = ORG_PHASE
    apex_only = True
    concurrency = 1
    timeout = 90.0
    rate_group = "gleif"
    noncommercial = False
    licence_note = "GLEIF LEI data is published under CC0; access through the API is free. Legal entities and their group only; no natural persons."

    async def run(self, entity: Entity, ctx: ModuleContext) -> list[Observation | Fact]:
        state = get_state(ctx)
        out: list[Fact] = []
        headers = {"User-Agent": POLITE_UA, "Accept": "application/vnd.api+json"}
        # A record reached by the LEI Wikidata holds for this organisation is the organisation's own legal entity, and
        # only then are its parents and children followed. An exact legal-name search is recorded too, but its hits are
        # UNCONFIRMED: the same name can belong to an unrelated entity (e.g. "ICANN" matches a Mexican real-estate
        # company), so they are never expanded and the section marks them as unconfirmed name matches.
        if state is not None and state.lei:
            rec = await self._record_by_lei(state.lei, ctx, headers, out)
            if rec:
                await self._relationships(state.lei, ctx, headers, out)
                return out
        for name in (state.known_names() if state is not None else []):
            if await self._by_name(name, ctx, headers, out):
                break
        return out

    def _fact(self, request: str, payload: dict) -> Fact:
        return Fact(Evidence.create(GLEIF_SOURCE, request, json.dumps(payload, sort_keys=True)))

    @staticmethod
    def _projection(rec: dict) -> dict:
        attr = rec.get("attributes", {})
        ent = attr.get("entity", {})
        addr = ent.get("legalAddress", {}) or {}
        return {
            "lei": attr.get("lei") or rec.get("id"),
            "legal_name": (ent.get("legalName") or {}).get("name"),
            "status": ent.get("status"),
            "jurisdiction": ent.get("jurisdiction"),
            "country": addr.get("country"),
            "city": addr.get("city"),
            "registered_as": ent.get("registeredAs"),
            "registration_authority": (ent.get("registeredAt") or {}).get("id"),
            "as_of": (attr.get("registration") or {}).get("lastUpdateDate"),
        }

    async def _record_by_lei(self, lei: str, ctx, headers, out) -> dict | None:
        url = f"https://api.gleif.org/api/v1/lei-records/{quote(lei, safe='')}"
        resp = await ctx.http.get(url, headers=headers)
        if resp.status_code == 404:
            out.append(self._fact(f"GLEIF lei-record {lei}", {"lei": lei, "found": False}))
            return None
        if resp.status_code != 200:
            raise http_failure(GLEIF_SOURCE, resp.status_code)
        data = resp.json().get("data")
        if not isinstance(data, dict):
            return None
        proj = self._projection(data)
        out.append(self._fact(f"GLEIF lei-record {lei}", proj))
        return proj

    async def _by_name(self, name: str, ctx, headers, out) -> list[str]:
        url = "https://api.gleif.org/api/v1/lei-records?page[size]=5&filter[entity.legalName]=" + quote(name, safe="")
        resp = await ctx.http.get(url, headers=headers)
        if resp.status_code != 200:
            raise http_failure(GLEIF_SOURCE, resp.status_code)
        data = resp.json().get("data") or []
        records = [self._projection(rec) for rec in data if isinstance(rec, dict)]
        out.append(self._fact(f"GLEIF legal-name {name}", {"legal_name": name, "total": len(records), "records": records}))
        return [r["lei"] for r in records if r.get("lei")]

    async def _relationships(self, lei: str, ctx, headers, out) -> None:
        for rel, path in (("direct-parent", "direct-parent"), ("ultimate-parent", "ultimate-parent")):
            url = f"https://api.gleif.org/api/v1/lei-records/{quote(lei, safe='')}/{path}"
            resp = await ctx.http.get(url, headers=headers)
            if resp.status_code == 404:
                out.append(self._fact(f"GLEIF {rel} {lei}", {"lei": lei, "relation": rel, "parent": None}))
                continue
            if resp.status_code != 200:
                raise http_failure(GLEIF_SOURCE, resp.status_code)
            data = resp.json().get("data")
            proj = self._projection(data) if isinstance(data, dict) else None
            out.append(self._fact(f"GLEIF {rel} {lei}", {"lei": lei, "relation": rel, "parent": proj}))
        url = f"https://api.gleif.org/api/v1/lei-records/{quote(lei, safe='')}/direct-children?page[size]={MAX_CHILDREN}"
        resp = await ctx.http.get(url, headers=headers)
        if resp.status_code == 404:
            out.append(self._fact(f"GLEIF direct-children {lei}", {"lei": lei, "relation": "direct-children", "total": 0, "children": []}))
            return
        if resp.status_code != 200:
            raise http_failure(GLEIF_SOURCE, resp.status_code)
        body = resp.json()
        total = (body.get("meta", {}).get("pagination", {}) or {}).get("total", 0)
        children = []
        for rec in (body.get("data") or [])[:MAX_CHILDREN]:
            proj = self._projection(rec) if isinstance(rec, dict) else None
            if proj and usable_org(proj.get("legal_name")):
                children.append({"lei": proj["lei"], "name": proj["legal_name"], "country": proj["country"]})
        out.append(self._fact(f"GLEIF direct-children {lei}", {"lei": lei, "relation": "direct-children", "total": total, "children": children}))
