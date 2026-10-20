"""Authorised organisation exposure (design D18): how much of an organisation's social-engineering surface its own
publications give away. Aggregate by default; never a way to look a person up.

Collection (modules/exposure_*.py, only through `scrutator exposure` with a valid engagement file) reads what the
organisation itself publishes: its site (security.txt, the home page and a few contact or about pages it links to,
robots.txt honoured), its DNS (DMARC report addresses, the SOA contact), its registration data (RDAP contacts) and the
public code organisations named in the engagement file (commit author addresses). Nothing else: no professional
networks, no social profiles, no search engines, no breach data (breach counts are designed as counts only and are not
wired to any service, see `breach_counts`).

**Minimisation happens at collection.** Every e-mail address found is reduced before anything is stored:

- an address outside the engagement's domains is dropped and only counted;
- a role mailbox (security@, billing@, hr@ ...) is kept as it is: it names a function, not a person;
- any other address is treated as a person's and kept only as its *shape* (`word.word`, `initial.word`, `word`) and a
  pseudonym (an HMAC under a random key that lives for one run and is never stored, so two sightings of one address
  count once but the pseudonym cannot be turned back into the address).

So the evidence, the report, the HTML and the bundle hold no personal address at all. With `--detail` (logged in the
audit log) the person-like addresses of this run are written to a separate file next to the report, never into the
report or the bundle. Phone numbers, names, postal addresses and anything else on a page are never extracted.

The derivation (`org_exposure`) is a pure function of the report's minimised evidence and its engagement record, so
`scrutator verify` re-derives it (check `org exposure derivable`).
"""

import hashlib
import hmac
import json
import re
from collections import Counter
from typing import Any

SOURCES = ("exposure_site", "exposure_dns", "exposure_rdap", "exposure_repos")
MAX_ADDRESSES = 500  # addresses read from one page or answer; a hostile page cannot grow a record without bound
EMAIL = re.compile(r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9][A-Za-z0-9._%+-]{0,63})@((?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24})(?![A-Za-z0-9-])")

FUNCTIONS = {
    "security": ("security", "abuse", "cert", "csirt", "psirt", "soc", "vulnerability", "vulnerabilities", "disclosure", "bugbounty"),
    "it": ("it", "helpdesk", "admin", "administrator", "hostmaster", "postmaster", "webmaster", "noc", "sysadmin", "dns", "root", "servicedesk", "itsupport"),
    "finance": ("finance", "billing", "invoice", "invoices", "accounts", "accounting", "payments", "payroll", "ap", "ar", "procurement", "purchasing"),
    "hr": ("hr", "jobs", "careers", "career", "recruiting", "recruitment", "talent", "apply", "hiring"),
    "sales": ("sales", "partners", "partner", "business", "biz", "orders"),
    "support": ("support", "help", "service", "customerservice", "care", "feedback"),
    "legal": ("legal", "privacy", "dpo", "gdpr", "compliance", "dataprotection"),
    "press": ("press", "media", "marketing", "pr", "communications", "comms", "news", "events"),
    "general": ("info", "contact", "hello", "office", "enquiries", "inquiries", "mail", "team", "general", "reception"),
    "automation": ("dmarc", "noreply", "no-reply", "donotreply", "do-not-reply", "bounce", "bounces", "mailer-daemon", "reports", "notifications", "rua", "ruf"),
}
_ROLE = {word: function for function, words in FUNCTIONS.items() for word in words}
_QUALIFIERS = frozenset({"team", "reports", "report", "desk", "dept", "department", "office", "group", "ops", "inbox", "mail",
                         "request", "requests", "only", "intl", "global", "emea", "apac", "americas", "hq"})

INFERENCES = {
    "pattern": "{count} of {people} person-like work addresses share the shape {shape}: someone who knows an employee's name can probably guess a working address.",
    "finance": "A finance or billing mailbox is published: a usual target for invoice fraud and payment-redirection pretexts.",
    "it": "An IT or administration mailbox is published: a pretext channel for password-reset and IT-support phishing.",
    "hr": "A recruitment or HR mailbox is published: a channel for malicious attachments disguised as applications.",
    "repos": "Commit metadata in the organisation's public code repositories gives away {count} work address(es) of people.",
    "none": "No work address was found in the sources read; that does not prove none is public.",
}


def role_function(local: str) -> str | None:
    """The function a mailbox name stands for (security, finance, ...), or None for anything that may be a person."""
    local = local.lower()
    if local in _ROLE:
        return _ROLE[local]
    # "security-team", "dmarc_reports", "billing.de": a role word followed only by qualifiers. "billing.jane.doe" is not a
    # role mailbox (it would keep a name), so every other part must be a qualifier, a role word, digits or a country code
    tokens = [t for t in re.split(r"[._+-]", local) if t]
    if len(tokens) >= 2 and tokens[0] in _ROLE and len(tokens[0]) > 2:
        if all(t in _QUALIFIERS or t in _ROLE or t.isdigit() or (len(t) == 2 and t.isalpha()) for t in tokens[1:]):
            return _ROLE[tokens[0]]
    return None


def shape(local: str) -> str:
    """The shape of a person-like mailbox name, never the name: `word.word`, `initial.word`, `word_word`, `word`,
    `word+digits`..."""
    local = local.lower().split("+", 1)[0]
    parts = re.split(r"([._-])", local)
    tokens, seps = parts[0::2], parts[1::2]
    out = []
    for token in tokens:
        if not token:
            out.append("")
        elif token.isdigit():
            out.append("digits")
        elif len(token) == 1 and token.isalpha():
            out.append("initial")
        elif re.fullmatch(r"[a-z]+", token):
            out.append("word")
        elif re.fullmatch(r"[a-z]+\d+", token):
            out.append("word+digits")
        else:
            out.append("mixed")
    text = out[0]
    for sep, token in zip(seps, out[1:]):
        text += sep + token
    return text[:40]


class Minimiser:
    """Turns raw addresses into what may be stored (see the module docstring). One per run: its key is random, lives in
    memory only, and goes away with the run."""

    def __init__(self, covers, key: bytes, detail: list | None = None) -> None:
        self.covers = covers
        self.key = key
        self.detail = detail  # a list only with --detail: person-like addresses of this run, for the separate file

    def reduce(self, addresses, where: str) -> dict:
        kept: dict[tuple, dict] = {}
        outside = 0
        for raw in list(addresses)[:MAX_ADDRESSES]:
            match = EMAIL.fullmatch(str(raw).strip().strip("<>").removeprefix("mailto:").split("?", 1)[0])
            if not match:
                continue
            local, domain = match.group(1).lower(), match.group(2).lower().rstrip(".")
            if not self.covers(domain):
                outside += 1
                continue
            function = role_function(local)
            if function:
                item = {"kind": "role", "local": local, "domain": domain, "function": function}
            else:
                ref = "p-" + hmac.new(self.key, f"{local}@{domain}".encode(), hashlib.sha256).hexdigest()[:16]
                item = {"kind": "person", "shape": shape(local), "domain": domain, "ref": ref}
                if self.detail is not None:
                    self.detail.append({"address": f"{local}@{domain}", "shape": item["shape"], "ref": ref, "found_at": where})
            kept[tuple(sorted(item.items()))] = item
        return {"addresses": sorted(kept.values(), key=lambda i: json.dumps(i, sort_keys=True)), "outside_engagement": outside}


def find_addresses(text: str) -> list[str]:
    """E-mail addresses in a text (and mailto: links). Nothing else is ever extracted: no names, phones or places."""
    return [f"{m.group(1)}@{m.group(2)}" for m in EMAIL.finditer(text)]


# ------------------------------------------------------------------------------------------- derivation


def _payload(record: dict) -> dict:
    try:
        value = json.loads(record.get("payload", ""))
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def org_exposure(report: dict) -> dict | None:
    """The aggregate exposure section, from the report's minimised evidence and its engagement record; None when the
    report has no exposure evidence."""
    evidence = report.get("evidence") or {}
    rows = [(i, r) for i, r in sorted(evidence.items()) if isinstance(r, dict) and r.get("source") in SOURCES]
    if not rows:
        return None
    engagement = report.get("engagement") or {}
    domains = [str(d) for d in engagement.get("domains", [])]

    def covered(domain: str) -> bool:
        return any(domain == d or domain.endswith("." + d) for d in domains)

    roles: dict[str, dict] = {}
    people: dict[str, dict] = {}
    by_source: Counter = Counter()
    outside = 0
    for evidence_id, record in rows:
        payload = _payload(record)
        outside += int(payload.get("outside_engagement") or 0) if isinstance(payload.get("outside_engagement"), int) else 0
        for item in payload.get("addresses", []) if isinstance(payload.get("addresses"), list) else []:
            if not isinstance(item, dict) or not covered(str(item.get("domain", ""))):
                continue
            if item.get("kind") == "role" and isinstance(item.get("local"), str):
                key = f"{item['local']}@{item['domain']}"
                entry = roles.setdefault(key, {"address": key, "function": role_function(item["local"]) or "general", "evidence_ids": []})
                entry["evidence_ids"].append(evidence_id)
            elif item.get("kind") == "person" and isinstance(item.get("ref"), str):
                entry = people.setdefault(item["ref"], {"shape": str(item.get("shape", ""))[:40], "evidence_ids": [], "sources": set()})
                entry["evidence_ids"].append(evidence_id)
                entry["sources"].add(record["source"])
            else:
                continue
            by_source[record["source"]] += 1
    shapes = Counter(p["shape"] for p in people.values())
    functions = Counter(r["function"] for r in roles.values())
    inferences = []
    if people:
        top, count = sorted(shapes.items(), key=lambda kv: (-kv[1], kv[0]))[0]
        if len(people) >= 2 and count / len(people) >= 0.6 and top != "word":
            ids = sorted({i for p in people.values() if p["shape"] == top for i in p["evidence_ids"]})
            inferences.append({"kind": "pattern", "text": INFERENCES["pattern"].format(count=count, people=len(people), shape=top), "evidence_ids": ids})
        repo_people = [p for p in people.values() if "exposure_repos" in p["sources"]]
        if repo_people:
            ids = sorted({i for p in repo_people for i in p["evidence_ids"]})
            inferences.append({"kind": "repos", "text": INFERENCES["repos"].format(count=len(repo_people)), "evidence_ids": ids})
    for function in ("finance", "it", "hr"):
        if functions.get(function):
            ids = sorted({i for r in roles.values() if r["function"] == function for i in r["evidence_ids"]})
            inferences.append({"kind": function, "text": INFERENCES[function], "evidence_ids": ids})
    if not people and not roles:
        inferences.append({"kind": "none", "text": INFERENCES["none"], "evidence_ids": sorted(i for i, _ in rows)})
    return {
        "organisation": engagement.get("organisation"),
        "addresses": {"distinct": len(roles) + len(people), "role": len(roles), "person_like": len(people), "outside_engagement_dropped": outside},
        "role_mailboxes": [{**r, "evidence_ids": sorted(set(r["evidence_ids"]))} for _, r in sorted(roles.items())],
        "functions": dict(sorted(functions.items())),
        "naming_patterns": [
            {"shape": s, "count": c, "share": round(c / len(people), 2)} for s, c in sorted(shapes.items(), key=lambda kv: (-kv[1], kv[0]))
        ],
        "sources": dict(sorted(by_source.items())),
        "inferences": inferences,
        "evidence_records": len(rows),
    }


def engagement_record(audit: list[dict]) -> dict | None:
    """The engagement the signed audit log records (the first `engagement` event), as the report carries it."""
    for record in audit:
        if record.get("event") == "engagement":
            return {k: record.get(k) for k in ("sha256", "organisation", "domains", "authorised_by", "start", "end", "purpose", "github_orgs", "confirmed")}
    return None


# ------------------------------------------------------------------------------------------- breach counts (not wired)


def breach_counts(response: Any) -> dict:
    """Counts only, from a breach service's per-domain answer shaped like Have I Been Pwned's v3 `breacheddomain`
    endpoint ({alias: [breach names]}). The aliases (people) are dropped here, before anything could store them.

    Not wired: no command calls a breach service. Using one needs that service's own domain verification and terms
    review, and a key (`SCRUTATOR_HIBP_KEY` would be the variable); this function is what any wiring must go through,
    so that only these two numbers ever leave it."""
    if not isinstance(response, dict):
        return {"addresses": 0, "breaches": 0}
    breaches = {str(b) for names in response.values() if isinstance(names, list) for b in names}
    return {"addresses": sum(1 for names in response.values() if isinstance(names, list) and names), "breaches": len(breaches)}
