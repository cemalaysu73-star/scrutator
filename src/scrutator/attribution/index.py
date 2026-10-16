"""A read-only index over a report, for the attribution signals.

Unlike the risk index (risk/view.py), which only reads in-scope names, this one also reads what
was collected about candidates: their DNS answers, certificates and registration records. A
candidate is only ever looked at passively, so those records exist only for names the scan was
allowed to enrich. Everything here comes from the report's entities, edges, evidence and scope,
so attribution can be recomputed from a proof bundle.
"""

import json
import re
from collections import defaultdict
from dataclasses import dataclass
from functools import cached_property

from scrutator.model.canonical import canonical_host
from scrutator.modules._names import usable_org
from scrutator.packs import PackSet
from scrutator.resolver import DnsAnswer, parse_payload
from scrutator.risk.view import host, parse_time, txt_values
from scrutator.scope import ScopePolicy

_DNS = re.compile(r"DNS (A|AAAA|CNAME|MX|NS|TXT|CAA) (\S+)")
_SPF_REF = re.compile(r"(?i)(?:\binclude:|\bredirect=)([^\s]+)")


@dataclass(frozen=True)
class Cert:
    """One certificate row from a crt.sh record."""

    evidence_id: str
    cert_id: str
    issuer: str
    names: tuple[str, ...]
    not_before: str
    not_after: str
    collected_at: str


def _clean_name(raw: str) -> str | None:
    try:
        return canonical_host(raw.strip().lower().removeprefix("*."))
    except ValueError:
        return None


class Index:
    def __init__(self, report: dict, packs: PackSet) -> None:
        self.packs = packs
        scope = report.get("scope")
        self.policy = ScopePolicy(**scope) if scope else None
        self.entities = {e["id"]: e for e in report["entities"]}
        self.edges = report["edges"]
        self.evidence = report["evidence"]
        self.names: set[str] = {
            e["value"]
            for e in self.entities.values()
            if e["type"] == "domain" and e["state"] == "in" and self._allowed(e["value"])
        }
        self._from: dict[tuple[str, str], list[dict]] = defaultdict(list)
        for edge in self.edges:
            self._from[(edge["src"], edge["rel"])].append(edge)
        self._dns: dict[tuple[str, str], tuple[DnsAnswer, str]] = {}
        self._scope: dict[str, bool] = {}
        self.certs: list[Cert] = []
        for evidence_id in sorted(self.evidence):
            self._index(evidence_id, self.evidence[evidence_id])

    def _allowed(self, value: str) -> bool:
        return self.policy is None or self.policy.decide(value).allowed

    # scope

    def in_scope(self, name: str) -> bool:
        """True for a name the scan's scope covers, whether or not the scan saw it as an entity."""
        name = host(name)
        if name not in self._scope:
            self._scope[name] = self.policy.decide(name).allowed if self.policy is not None else name in self.names
        return self._scope[name]

    def universe(self) -> list[str]:
        """Domain entities outside the scope, which attribution may score. A name that was
        promoted into scope after the scan stays here, so its attribution is still explained."""
        return sorted(
            e["value"] for e in self.entities.values() if e["type"] == "domain" and e["value"] not in self.names
        )

    # records

    def _index(self, evidence_id: str, record: dict) -> None:
        source, request = record["source"], record["request"]
        if source == "dns":
            match = _DNS.fullmatch(request)
            if match:
                rtype, raw = match.groups()
                try:
                    name = canonical_host(raw)
                except ValueError:
                    return
                self._dns.setdefault((rtype, name), (parse_payload(record["payload"]), evidence_id))
        elif source == "crtsh":
            try:
                rows = json.loads(record["payload"])
            except ValueError:
                return
            if not isinstance(rows, list):
                return
            for row in rows:
                if not isinstance(row, dict):
                    continue
                names = tuple(
                    sorted({n for n in (_clean_name(x) for x in str(row.get("name_value", "")).splitlines()) if n})
                )
                if names:
                    self.certs.append(
                        Cert(
                            evidence_id,
                            str(row.get("id", "")),
                            str(row.get("issuer_name", "")),
                            names,
                            str(row.get("not_before", "")),
                            str(row.get("not_after", "")),
                            record["collected_at"],
                        )
                    )

    def dns(self, rtype: str, name: str) -> tuple[DnsAnswer, str] | None:
        return self._dns.get((rtype, host(name)))

    def targets(self, rtype: str, name: str) -> tuple[list[str], str] | None:
        """Host names in the answers of an NS or MX lookup, and the evidence they came from."""
        found = self.dns(rtype, name)
        if found is None or found[0].status != "answer":
            return None
        names = []
        for record in found[0].records:
            token = record.split()[-1] if record.split() else ""
            if token not in ("", "."):
                names.append(host(token))
        return (sorted(set(names)), found[1]) if names else None

    def spf_targets(self, name: str) -> tuple[list[str], str] | None:
        found = self.dns("TXT", name)
        if found is None or found[0].status != "answer":
            return None
        names = []
        for value in txt_values(found[0].records):
            if "v=spf1" in value.lower():
                names.extend(host(t) for t in _SPF_REF.findall(value))
        return (sorted(set(names)), found[1]) if names else None

    def zone_apexes(self) -> list[str]:
        return sorted(n for n in self.names if self.targets("NS", n) is not None)

    # tables over the in-scope names, built once: a scan can have thousands of candidates, and every
    # signal compares a candidate with the scope

    @cached_property
    def certs_by_name(self) -> dict[str, list[Cert]]:
        found: dict[str, list[Cert]] = defaultdict(list)
        for cert in self.certs:
            for name in cert.names:
                found[name].append(cert)
        return found

    @cached_property
    def scope_certs(self) -> list[Cert]:
        return [c for c in self.certs if any(self.in_scope(n) for n in c.names)]

    @cached_property
    def scope_issuers(self) -> dict[str, list[Cert]]:
        """Certificates that list an in-scope name, by lower-case issuer."""
        found: dict[str, list[Cert]] = defaultdict(list)
        for cert in self.scope_certs:
            if cert.issuer.strip():
                found[cert.issuer.strip().lower()].append(cert)
        return found

    @cached_property
    def scope_zones(self) -> dict[str, tuple[list[str], str]]:
        """In-scope zone apex -> (its name servers, the evidence)."""
        return {name: self.targets("NS", name) for name in sorted(self.names) if self.targets("NS", name) is not None}

    @cached_property
    def mx_users(self) -> dict[str, list[tuple[str, str]]]:
        """Mail host -> [(in-scope name that uses it, evidence)]."""
        found: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for name in sorted(self.names):
            targets = self.targets("MX", name)
            if targets is not None:
                for target in targets[0]:
                    found[target].append((name, targets[1]))
        return found

    @cached_property
    def uses(self) -> dict[str, list[tuple[str, str, str, str]]]:
        """Host -> [(in-scope name, what it uses the host for, kind of pack entry, evidence)] for the
        name servers, mail hosts and SPF includes of the in-scope names."""
        found: dict[str, list[tuple[str, str, str, str]]] = defaultdict(list)
        for name in sorted(self.names):
            for label, kind, targets in (
                ("name servers", "ns", self.targets("NS", name)),
                ("mail", "mx", self.targets("MX", name)),
                ("SPF", "spf", self.spf_targets(name)),
            ):
                if targets is not None:
                    for target in targets[0]:
                        found[target].append((name, label, kind, targets[1]))
        return found

    @cached_property
    def registrant_holders(self) -> dict[str, list[tuple[str, str, tuple[str, ...]]]]:
        """Case-folded registrant -> [(in-scope name, registrant as written, evidence)]."""
        found: dict[str, list[tuple[str, str, tuple[str, ...]]]] = defaultdict(list)
        for name in sorted(self.names):
            for org, evidence in self.registrants(name):
                found[org.casefold()].append((name, org, evidence))
        return found

    @cached_property
    def scope_networks(self) -> dict[tuple[str, str], list[tuple[str, tuple[str, ...], list[tuple[str, str, tuple[str, ...]]]]]]:
        """(kind, value) of a network -> [(address, its evidence, all its networks)] over the in-scope addresses."""
        found: dict = defaultdict(list)
        seen: set[str] = set()
        for name in sorted(self.names):
            for ip, evidence in self.addresses(name):
                if ip in seen:
                    continue
                seen.add(ip)
                networks = self.networks(ip)
                for kind, value, _ in networks:
                    found[(kind, value)].append((ip, evidence, networks))
        return found

    # graph

    def edges_from(self, src_id: str, rel: str) -> list[dict]:
        return self._from.get((src_id, rel), [])

    def registrants(self, name: str) -> list[tuple[str, tuple[str, ...]]]:
        """Usable registrant organisations of a domain, with the evidence that names them."""
        found = []
        for edge in self.edges_from(f"domain:{name}", "registrant"):
            org = self.entities.get(edge["dst"])
            text = usable_org(org["value"]) if org else None
            if text:
                found.append((text, tuple(edge["evidence_ids"])))
        return found

    def addresses(self, name: str) -> list[tuple[str, tuple[str, ...]]]:
        """Addresses a name resolves to, with the evidence for each."""
        found = []
        for edge in self.edges_from(f"domain:{name}", "resolves_to"):
            target = self.entities.get(edge["dst"])
            if target and target["type"] == "ip":
                found.append((target["value"], tuple(edge["evidence_ids"])))
        return found

    def networks(self, ip: str) -> list[tuple[str, str, tuple[str, ...]]]:
        """(kind, value, evidence) for the AS that announces an address and the owner of its
        netblock; kind is `asn` or `owner`."""
        found = []
        for rel, kind in (("announced_by", "asn"), ("netblock_owner", "owner")):
            for edge in self.edges_from(f"ip:{ip}", rel):
                target = self.entities.get(edge["dst"])
                if target:
                    value = target["value"] if kind == "asn" else " ".join(target["value"].lower().split())
                    found.append((kind, value, tuple(edge["evidence_ids"])))
        return found

    def certs_naming(self, name: str) -> list[Cert]:
        return self.certs_by_name.get(name, [])

    def expired_days(self, cert: Cert) -> float | None:
        """Days between the certificate's expiry and the moment the record was collected;
        negative while it was still valid. None if either time cannot be read."""
        end, collected = parse_time(cert.not_after), parse_time(cert.collected_at)
        if end is None or collected is None:
            return None
        return (collected - end).total_seconds() / 86400
