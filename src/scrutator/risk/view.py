"""A read-only index over a report's entities, edges and evidence.

Everything the risk rules know comes through here, and only about in-scope names. A hostile or
sloppy report that carries evidence about a name outside the scope gets that evidence ignored,
so a risk can never be derived from something the scan was not allowed to look at.
"""

import json
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone

from scrutator.model.canonical import canonical_host
from scrutator.packs import PackSet
from scrutator.resolver import DnsAnswer, parse_payload
from scrutator.scope import ScopePolicy

_DNS = re.compile(r"DNS (A|AAAA|CNAME|MX|NS|TXT|CAA) (\S+)")
_RDAP_DOMAIN = re.compile(r"GET https://rdap\.org/domain/(\S+)")
_NAMING_RELS = frozenset({"has_subdomain", "related_host"})
NAMING_SOURCES = frozenset({"crtsh", "wayback", "commoncrawl"})
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')


@dataclass(frozen=True)
class DnsRecord:
    rtype: str
    name: str
    answer: DnsAnswer
    evidence_id: str


def host(value: str) -> str:
    """A name as compared everywhere: lower case, no trailing dot."""
    return str(value).strip().lower().rstrip(".")


def txt_values(records) -> list[str]:
    """TXT answers as text: the quoted chunks of each record joined (a long TXT record is
    several quoted strings), or the raw record if it has no quotes."""
    values = []
    for record in records:
        chunks = _QUOTED.findall(record)
        values.append("".join(chunks) if chunks else record)
    return values


def parse_time(text: str) -> datetime | None:
    """An ISO timestamp as naive UTC, or None. RDAP and crt.sh disagree on whether there is a
    zone designator, so everything is normalised before it is compared."""
    try:
        moment = datetime.fromisoformat(str(text).strip())
    except ValueError:
        return None
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone.utc).replace(tzinfo=None)
    return moment


class View:
    def __init__(self, report: dict, packs: PackSet) -> None:
        self.packs = packs
        self.report = report
        scope = report.get("scope")
        self._policy = ScopePolicy(**scope) if scope else None
        self.entities = {e["id"]: e for e in report["entities"]}
        self.edges = report["edges"]
        self._from: dict[tuple[str, str], list[dict]] = defaultdict(list)
        self._into: dict[str, list[dict]] = defaultdict(list)
        for edge in self.edges:
            self._from[(edge["src"], edge["rel"])].append(edge)
            self._into[edge["dst"]].append(edge)
        self.evidence = report["evidence"]
        self.names: set[str] = {
            e["value"] for e in self.entities.values() if e["type"] == "domain" and self._in_scope(e)
        }
        self._dns: dict[tuple[str, str], DnsRecord] = {}
        self.rdap: dict[str, dict] = {}
        for evidence_id in sorted(self.evidence):
            self._index(evidence_id, self.evidence[evidence_id])

    def _in_scope(self, entity: dict) -> bool:
        if entity["state"] != "in":
            return False
        return self._policy is None or self._policy.decide(entity["value"]).allowed

    def _index(self, evidence_id: str, record: dict) -> None:
        request = record["request"]
        match = _DNS.fullmatch(request)
        if match and record["source"] == "dns":
            rtype, raw = match.groups()
            try:
                name = canonical_host(raw)
            except ValueError:
                return
            owner = name[len("_dmarc."):] if name.startswith("_dmarc.") else name
            if owner in self.names:
                self._dns.setdefault((rtype, name), DnsRecord(rtype, name, parse_payload(record["payload"]), evidence_id))
            return
        match = _RDAP_DOMAIN.fullmatch(request)
        if match and record["source"] == "rdap":
            try:
                name, data = canonical_host(match.group(1)), json.loads(record["payload"])
            except ValueError:
                return
            if name in self.names and isinstance(data, dict):
                self.rdap.setdefault(name, {"data": data, "evidence_id": evidence_id, "collected_at": record["collected_at"]})

    # DNS

    def dns(self, rtype: str, name: str) -> DnsRecord | None:
        return self._dns.get((rtype, name))

    def answers(self, rtype: str, name: str) -> list[str]:
        record = self.dns(rtype, name)
        return list(record.answer.records) if record and record.answer.status == "answer" else []

    def status(self, rtype: str, name: str) -> str | None:
        record = self.dns(rtype, name)
        return record.answer.status if record else None

    def targets(self, rtype: str, name: str) -> list[str]:
        """Host names in the answers of a CNAME, NS or MX record (a null MX has none)."""
        found = []
        for answer in self.answers(rtype, name):
            token = answer.split()[-1] if answer.split() else ""
            if token in ("", "."):
                continue
            found.append(host(token))
        return found

    def zone_apexes(self) -> list[str]:
        return sorted(name for name in self.names if self.answers("NS", name))

    def zone_of(self, name: str, zones: list[str]) -> str | None:
        """The longest zone apex that contains `name`."""
        containing = [z for z in zones if name == z or name.endswith("." + z)]
        return max(containing, key=len) if containing else None

    # graph

    def edges_from(self, src: str, rel: str) -> list[dict]:
        return self._from.get((src, rel), [])

    def edges_into(self, dst: str) -> list[dict]:
        return self._into.get(dst, [])

    def named_by(self) -> dict[str, list[tuple[str, str]]]:
        """For each in-scope name, the (source, evidence id) pairs of certificates and archives
        that name it."""
        found: dict[str, set[tuple[str, str]]] = {}
        for edge in self.edges:
            if edge["rel"] not in _NAMING_RELS:
                continue
            dst = self.entities.get(edge["dst"])
            if dst is None or dst["type"] != "domain" or dst["value"] not in self.names:
                continue
            for evidence_id in edge["evidence_ids"]:
                record = self.evidence.get(evidence_id)
                if record and record["source"] in NAMING_SOURCES:
                    found.setdefault(dst["value"], set()).add((record["source"], evidence_id))
        return {name: sorted(pairs) for name, pairs in found.items()}
