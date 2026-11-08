"""The Organisation section of a report: a pure function of the report's own organisation-phase evidence and scope, so
`scrutator verify` can re-derive it from a proof bundle and compare (check `organisation derivable`).

It reads the evidence the organisation modules stored (sources `wikidata`, `gleif`, `hibp`, `github`, `github_leaks`,
`packages`, `handles`), each a parsed JSON payload with a request that says what it is, and lays it out as: the legal
entities (confirmed by an LEI, or unconfirmed exact name matches kept apart), the parents and subsidiaries, the official
domains, the breach history, the GitHub account and repositories, the package namespaces and the public handles.
"""

import json

SOURCES = frozenset({"wikidata", "gleif", "hibp", "github", "github_leaks", "packages", "handles"})


def _records(report: dict):
    for evidence_id, record in sorted((report.get("evidence") or {}).items()):
        if isinstance(record, dict) and record.get("source") in SOURCES:
            request = str(record.get("request", ""))
            try:
                payload = json.loads(record.get("payload", ""))
            except (TypeError, ValueError):
                payload = None
            yield evidence_id, record["source"], request, payload


def _scope_roots(report: dict) -> set[str]:
    return {str(d) for d in (report.get("scope") or {}).get("domains", [])} | {str(report.get("scan", {}).get("seed", ""))}


def organisation(report: dict) -> dict | None:
    """The Organisation section, or None when the scan collected no organisation evidence."""
    rows = list(_records(report))
    if not rows:
        return None
    roots = {r for r in _scope_roots(report) if r}
    entities = {e["id"]: e for e in report.get("entities", [])}

    legal_entities: list[dict] = []
    name_matches: list[dict] = []
    parents: list[dict] = []
    subsidiaries: list[dict] = []
    official_domains: list[dict] = []
    wikidata_items: list[dict] = []
    breaches: list[dict] = []
    github = {"resolved": False}
    members = None
    repos: list[dict] = []
    github_named: list[str] = []
    github_abandoned: list[str] = []
    code_leaks: list[dict] = []
    package_rows: list[dict] = []
    handles: list[dict] = []

    for evidence_id, source, request, payload in rows:
        if payload is None:
            continue
        if source == "wikidata" and request.startswith("WIKIDATA site") or (source == "wikidata" and request.startswith("WIKIDATA label")):
            for item in payload.get("items", []):
                wikidata_items.append({**item, "evidence_id": evidence_id})
                for site in item.get("sites", []):
                    if site not in roots:
                        official_domains.append({"domain": site, "via": f"Wikidata {item.get('qid')}", "relation": "organisation", "evidence_id": evidence_id})
        elif source == "wikidata" and request.startswith("WIKIDATA relations"):
            for rel in payload.get("relations", []):
                bucket = parents if rel.get("rel") == "parent" else subsidiaries
                bucket.append({"name": rel.get("label"), "qid": rel.get("qid"), "via": "Wikidata", "evidence_id": evidence_id})
                for site in rel.get("sites", []):
                    if site not in roots:
                        official_domains.append({"domain": site, "via": f"Wikidata {rel.get('qid')}", "relation": rel.get("rel"), "evidence_id": evidence_id})
        elif source == "gleif" and request.startswith("GLEIF lei-record"):
            if payload.get("found") is not False and payload.get("lei"):
                legal_entities.append({**{k: payload.get(k) for k in ("lei", "legal_name", "status", "jurisdiction", "country", "city", "registered_as", "registration_authority", "as_of")}, "basis": "lei", "confirmed": True, "evidence_id": evidence_id})
        elif source == "gleif" and request.startswith("GLEIF legal-name"):
            for rec in payload.get("records", []):
                name_matches.append({**{k: rec.get(k) for k in ("lei", "legal_name", "status", "jurisdiction", "country", "city")}, "basis": "name-match", "confirmed": False, "query": payload.get("legal_name"), "evidence_id": evidence_id})
        elif source == "gleif" and (request.startswith("GLEIF direct-parent") or request.startswith("GLEIF ultimate-parent")):
            parent = payload.get("parent")
            if parent:
                parents.append({"relation": payload.get("relation"), "lei": parent.get("lei"), "name": parent.get("legal_name"), "country": parent.get("country"), "via": "GLEIF", "evidence_id": evidence_id})
        elif source == "gleif" and request.startswith("GLEIF direct-children"):
            for child in payload.get("children", []):
                subsidiaries.append({"relation": "direct-child", "lei": child.get("lei"), "name": child.get("name"), "country": child.get("country"), "via": "GLEIF", "evidence_id": evidence_id})
        elif source == "hibp":
            if isinstance(payload, list):
                for b in payload:
                    if isinstance(b, dict):
                        breaches.append({
                            "name": b.get("Name"), "title": b.get("Title"), "domain": b.get("Domain"),
                            "breach_date": b.get("BreachDate"), "added_date": b.get("AddedDate"),
                            "pwn_count": b.get("PwnCount"), "data_classes": [c for c in (b.get("DataClasses") or []) if isinstance(c, str)],
                            "is_verified": bool(b.get("IsVerified")), "is_sensitive": bool(b.get("IsSensitive")),
                            "evidence_id": evidence_id,
                        })
        elif source == "github" and request.startswith("GITHUB org"):
            if payload.get("resolved") is False or payload.get("found") is False:
                github = {"resolved": False, "reason": payload.get("reason") or "no GitHub account found", "evidence_id": evidence_id}
            else:
                github = {"resolved": True, **{k: payload.get(k) for k in ("login", "display_name", "is_verified", "public_repos", "created_at", "html_url")}, "evidence_id": evidence_id}
        elif source == "github" and request.startswith("GITHUB members"):
            members = payload.get("public_members")
        elif source == "github" and request.startswith("GITHUB repos"):
            for repo in payload.get("repos", []):
                repos.append({**repo, "evidence_id": evidence_id})
            github_named = [h for h in payload.get("named_in_scope_hosts", []) if isinstance(h, str)]
            github_abandoned = [h for h in payload.get("abandoned_named_hosts", []) if isinstance(h, str)]
        elif source == "github_leaks" and request.startswith("GITHUB code-leak "):
            code_leaks.append({**{k: payload.get(k) for k in ("repository", "path", "format", "commit_sha", "fingerprint", "mask")}, "evidence_id": evidence_id})
        elif source == "packages" and request.startswith("PACKAGE "):
            package_rows.append({**payload, "evidence_id": evidence_id})
        elif source == "handles" and request.startswith("HANDLE "):
            handles.append({**payload, "evidence_id": evidence_id})

    named_hosts = sorted(set(github_named))
    abandoned = sorted(set(github_abandoned))

    confirmed_ns = [p for p in package_rows if p.get("role") == "brand" and p.get("exists") and p.get("linked_host")]
    unregistered = [p for p in package_rows if p.get("role") == "brand" and p.get("exists") is False]
    lookalikes_existing = [p for p in package_rows if p.get("role") == "lookalike" and p.get("exists")]

    section = {
        "legal_entities": legal_entities,
        "name_matches": name_matches,
        "parents": _dedup(parents),
        "subsidiaries": _dedup(subsidiaries),
        "official_domains": _dedup_domains(official_domains),
        "wikidata": wikidata_items,
        "breaches": breaches,
        "github": {**github, "public_members": members, "repos": repos, "named_in_scope_hosts": named_hosts, "abandoned_named_hosts": abandoned, "code_leaks": code_leaks},
        "packages": {"checks": package_rows, "confirmed_namespaces": confirmed_ns, "unregistered_brand": unregistered, "lookalikes_existing": lookalikes_existing},
        "handles": handles,
    }
    section["summary"] = {
        "legal_entities": len(legal_entities),
        "unconfirmed_name_matches": len(name_matches),
        "parents": len(section["parents"]),
        "subsidiaries": len(section["subsidiaries"]),
        "official_domains": len(section["official_domains"]),
        "breaches": len(breaches),
        "github_repos": len(repos),
        "github_named_hosts": len(named_hosts),
        "code_leaks": len(code_leaks),
        "confirmed_namespaces": len(confirmed_ns),
        "lookalike_packages": len(lookalikes_existing),
        "unregistered_brand_namespaces": len(unregistered),
        "handles_found": sum(1 for h in handles if h.get("state") == "exists"),
    }
    return section


def _dedup(rows):
    seen, out = set(), []
    for r in rows:
        key = (r.get("relation"), r.get("lei"), (r.get("name") or "").casefold(), r.get("qid"))
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


def _dedup_domains(rows):
    seen, out = set(), []
    for r in sorted(rows, key=lambda r: (r["domain"], r.get("via", ""))):
        if r["domain"] not in seen:
            seen.add(r["domain"])
            out.append(r)
    return out
