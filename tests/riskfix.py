"""Builds report dictionaries the way a real scan produces them, from reserved names only
(example.com / example.net, 192.0.2.0/24, 198.51.100.0/24). The evidence shapes are copied from
a real scan of example.com: DNS payloads are one record per line, TXT text is quoted, crt.sh
payloads are lists of certificate rows with issuer_name / name_value / not_before / not_after,
RDAP payloads carry an events list."""

import hashlib
import json

from scrutator.packs import load_packs

COLLECTED = "2026-10-16T12:00:00+00:00"


def evidence_id(source, request, payload):
    return hashlib.sha256(f"{source}\n{request}\n{payload}".encode()).hexdigest()


class Zone:
    def __init__(self, domains=("example.com",), collected=COLLECTED):
        self.scope = {"domains": list(domains), "cidrs": [], "asns": []}
        self.collected = collected
        self.entities: dict[str, dict] = {}
        self.edges: list[dict] = []
        self.evidence: dict[str, dict] = {}

    # entities

    def entity(self, kind, value, state):
        entity_id = f"{kind}:{value}"
        self.entities.setdefault(entity_id, {"id": entity_id, "type": kind, "value": value, "state": state})
        return entity_id

    def name(self, value, state="in"):
        return self.entity("domain", value, state)

    # evidence

    def ev(self, source, request, payload, collected=None):
        eid = evidence_id(source, request, payload)
        self.evidence[eid] = {
            "source": source,
            "request": request,
            "payload": payload,
            "collected_at": collected or self.collected,
        }
        return eid

    def dns(self, rtype, name, answer):
        """`answer` is a list of records, or the string NXDOMAIN / NODATA."""
        payload = answer if isinstance(answer, str) else "\n".join(answer)
        return self.ev("dns", f"DNS {rtype} {name}", payload)

    def edge(self, src, rel, dst, *evidence_ids):
        self.edges.append({"src": src, "rel": rel, "dst": dst, "evidence_ids": sorted(evidence_ids)})

    # the shapes a scan produces

    def host(self, value, addresses=("192.0.2.10",), state="in"):
        """A name with A records, and a relation to each address."""
        src = self.name(value, state)
        eid = self.dns("A", value, list(addresses))
        for address in addresses:
            self.edge(src, "resolves_to", self.entity("ip", address, "linked"), eid)
        return src

    def cname(self, value, target, address="NXDOMAIN"):
        """A name that is an alias of `target`; `address` is what its A lookup returned."""
        src = self.name(value)
        cid = self.dns("CNAME", value, [target + "."])
        self.edge(src, "cname_to", self.name(target, "out"), cid)
        aid = self.dns("A", value, address if isinstance(address, str) else list(address))
        if not isinstance(address, str):
            for ip in address:
                self.edge(src, "resolves_to", self.entity("ip", ip, "linked"), aid)
        return src

    def ns(self, value, servers):
        src = self.name(value)
        eid = self.dns("NS", value, [s + "." for s in servers])
        for server in servers:
            self.edge(src, "ns", self.name(server, "out"), eid)
        return eid

    def mx(self, value, exchanges):
        src = self.name(value)
        eid = self.dns("MX", value, [f"{10 * (n + 1)} {x}." for n, x in enumerate(exchanges)])
        for exchange in exchanges:
            self.edge(src, "mx", self.name(exchange, "out"), eid)
        return eid

    def txt(self, value, *texts):
        self.name(value)
        return self.dns("TXT", value, [f'"{t}"' for t in texts])

    def found(self, value, source="crtsh", root="example.com", issuer="C=US, O=Let's Encrypt, CN=R3", not_before="2026-09-01T00:00:00", not_after="2026-12-01T00:00:00"):
        """A certificate or archive source naming `value`."""
        dst = self.name(value)
        if source == "crtsh":
            payload = json.dumps(
                [{"id": 1, "issuer_name": issuer, "name_value": value, "not_after": not_after, "not_before": not_before}],
                sort_keys=True,
            )
            request = "GET https://crt.sh/?q=%25.example.com&output=json"
        else:
            payload = json.dumps([f"http://{value}/"])
            request = f"GET https://web.archive.org/cdx/search/cdx?url=%2A.{value}&output=json"
        eid = self.ev(source, request, payload)
        self.edge(self.name(root), "has_subdomain", dst, eid)
        return eid

    def rdap(self, value, expiry, nameservers=()):
        payload = json.dumps(
            {
                "ldhName": value.upper(),
                "events": [
                    {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
                    {"eventAction": "expiration", "eventDate": expiry},
                ],
                "nameservers": [{"ldhName": n.upper()} for n in nameservers],
            },
            sort_keys=True,
        )
        return self.ev("rdap", f"GET https://rdap.org/domain/{value}", payload)

    def announced(self, ip, asn, owner="EXAMPLE-NET"):
        ip_id, asn_id = self.entity("ip", ip, "linked"), self.entity("asn", asn, "out")
        eid = self.ev("asn", f"GET https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}", json.dumps({"data": {"asns": [{"asn": int(asn[2:])}]}}))
        self.edge(ip_id, "announced_by", asn_id, eid)
        return eid

    def report(self, packs=None):
        packs = packs or load_packs()
        return {
            "scope": self.scope,
            "entities": sorted(self.entities.values(), key=lambda e: e["id"]),
            "edges": self.edges,
            "evidence": self.evidence,
            "packs": packs.to_dict(),
        }
